
C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\test_samples\fmt_cve\fmt_06_printf_fgets\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 bf 85 00 00       	call   1400095e8 <fflush>
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
   14000113b:	e8 58 84 00 00       	call   140009598 <_amsg_exit>
   140001140:	48 8b 05 29 a5 00 00 	mov    rax,QWORD PTR [rip+0xa529]        # 14000b670 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 18 a5 00 00 	mov    rax,QWORD PTR [rip+0xa518]        # 14000b670 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 58 7e 00 00       	call   140008fc0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 a7 84 00 00       	call   140009628 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 37 84 00 00       	call   1400095d0 <abort>
   140001199:	e8 22 11 00 00       	call   1400022c0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 5b a5 00 00 	mov    rax,QWORD PTR [rip+0xa55b]        # 14000b700 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 99 f0 00 00 	mov    rax,QWORD PTR [rip+0xf099]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 98 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa498]        # 14000b650 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 96 7d 00 00       	call   140008f60 <_set_invalid_parameter_handler>
   1400011ca:	e8 01 1a 00 00       	call   140002bd0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 2f a4 00 00 	mov    rax,QWORD PTR [rip+0xa42f]        # 14000b610 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 97 83 00 00       	call   140009588 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 8b 83 00 00       	call   140009588 <__set_app_type>
   1400011fd:	e8 0e 7c 00 00       	call   140008e10 <__p__fmode>
   140001202:	48 8b 15 e7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4e7]        # 14000b6f0 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 0e 7c 00 00       	call   140008e20 <__p__commode>
   140001212:	48 8b 15 b7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b7]        # 14000b6d0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 7e 06 00 00       	call   1400018a0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 63 83 00 00       	call   140009598 <_amsg_exit>
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
   140001265:	e8 36 7d 00 00       	call   140008fa0 <_configthreadlocale>
   14000126a:	48 8b 15 4f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa44f]        # 14000b6c0 <.refptr.__xi_z>
   140001271:	48 8b 05 38 a4 00 00 	mov    rax,QWORD PTR [rip+0xa438]        # 14000b6b0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 30 7b 00 00       	call   140008db0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 0a 83 00 00       	call   140009598 <_amsg_exit>
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
   1400012cb:	e8 a8 82 00 00       	call   140009578 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 b5 82 00 00       	call   140009598 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 8e 82 00 00       	call   140009598 <_amsg_exit>
   14000130a:	48 8b 15 8f a3 00 00 	mov    rdx,QWORD PTR [rip+0xa38f]        # 14000b6a0 <.refptr.__xc_z>
   140001311:	48 8b 05 78 a3 00 00 	mov    rax,QWORD PTR [rip+0xa378]        # 14000b690 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 90 82 00 00       	call   1400095b0 <_initterm>
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
   14000138d:	e8 9e 7a 00 00       	call   140008e30 <__p___initenv>
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
   1400013cc:	e8 0f 82 00 00       	call   1400095e0 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 c0 81 00 00       	call   1400095a0 <_cexit>
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
   140001511:	e8 02 81 00 00       	call   140009618 <malloc>
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
   14000155c:	e8 df 80 00 00       	call   140009640 <strlen>
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
   140001585:	e8 8e 80 00 00       	call   140009618 <malloc>
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
   1400015e8:	e8 33 80 00 00       	call   140009620 <memcpy>
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
   140001642:	e8 81 7f 00 00       	call   1400095c8 <_crt_atexit>
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
   140001764:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
   14000176b:	e8 07 01 00 00       	call   140001877 <__main>
   140001770:	b9 00 00 00 00       	mov    ecx,0x0
   140001775:	48 8b 05 a4 89 00 00 	mov    rax,QWORD PTR [rip+0x89a4]        # 14000a120 <__imp___acrt_iob_func>
   14000177c:	ff d0                	call   rax
   14000177e:	48 89 c2             	mov    rdx,rax
   140001781:	48 8d 45 80          	lea    rax,[rbp-0x80]
   140001785:	49 89 d0             	mov    r8,rdx
   140001788:	ba 80 00 00 00       	mov    edx,0x80
   14000178d:	48 89 c1             	mov    rcx,rax
   140001790:	e8 5b 7e 00 00       	call   1400095f0 <fgets>
   140001795:	48 85 c0             	test   rax,rax
   140001798:	75 07                	jne    1400017a1 <main+0x41>
   14000179a:	b8 00 00 00 00       	mov    eax,0x0
   14000179f:	eb 11                	jmp    1400017b2 <main+0x52>
   1400017a1:	48 8d 45 80          	lea    rax,[rbp-0x80]
   1400017a5:	48 89 c1             	mov    rcx,rax
   1400017a8:	e8 23 19 00 00       	call   1400030d0 <__mingw_printf>
   1400017ad:	b8 00 00 00 00       	mov    eax,0x0
   1400017b2:	48 81 c4 a0 00 00 00 	add    rsp,0xa0
   1400017b9:	5d                   	pop    rbp
   1400017ba:	c3                   	ret
   1400017bb:	90                   	nop
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
   140001a8c:	e8 2f 75 00 00       	call   140008fc0 <__acrt_iob_func>
   140001a91:	48 89 c1             	mov    rcx,rax
   140001a94:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001a98:	48 8d 05 f9 96 00 00 	lea    rax,[rip+0x96f9]        # 14000b198 <.rdata+0xf8>
   140001a9f:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001aa6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001aac:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001ab2:	49 89 d9             	mov    r9,rbx
   140001ab5:	49 89 d0             	mov    r8,rdx
   140001ab8:	48 89 c2             	mov    rdx,rax
   140001abb:	e8 38 7b 00 00       	call   1400095f8 <fprintf>
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
   140001b08:	e8 b3 74 00 00       	call   140008fc0 <__acrt_iob_func>
   140001b0d:	48 89 c1             	mov    rcx,rax
   140001b10:	48 8d 05 b9 96 00 00 	lea    rax,[rip+0x96b9]        # 14000b1d0 <.rdata>
   140001b17:	48 89 c2             	mov    rdx,rax
   140001b1a:	e8 d9 7a 00 00       	call   1400095f8 <fprintf>
   140001b1f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001b23:	b9 02 00 00 00       	mov    ecx,0x2
   140001b28:	e8 93 74 00 00       	call   140008fc0 <__acrt_iob_func>
   140001b2d:	48 89 c1             	mov    rcx,rax
   140001b30:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001b34:	49 89 d8             	mov    r8,rbx
   140001b37:	48 89 c2             	mov    rdx,rax
   140001b3a:	e8 11 7b 00 00       	call   140009650 <vfprintf>
   140001b3f:	e8 8c 7a 00 00       	call   1400095d0 <abort>
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
   140001cca:	48 8b 05 97 e5 00 00 	mov    rax,QWORD PTR [rip+0xe597]        # 140010268 <__imp_VirtualQuery>
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
   140001de4:	48 8b 05 75 e4 00 00 	mov    rax,QWORD PTR [rip+0xe475]        # 140010260 <__imp_VirtualProtect>
   140001deb:	ff d0                	call   rax
   140001ded:	85 c0                	test   eax,eax
   140001def:	75 1a                	jne    140001e0b <mark_section_writable+0x2c6>
   140001df1:	48 8b 05 18 e4 00 00 	mov    rax,QWORD PTR [rip+0xe418]        # 140010210 <__imp_GetLastError>
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
   140001ed4:	48 8b 05 85 e3 00 00 	mov    rax,QWORD PTR [rip+0xe385]        # 140010260 <__imp_VirtualProtect>
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
   140001f34:	e8 e7 76 00 00       	call   140009620 <memcpy>
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
   1400023f8:	e8 93 71 00 00       	call   140009590 <__setusermatherr>
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
   14000254e:	e8 dd 70 00 00       	call   140009630 <signal>
   140002553:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002557:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000255c:	75 1b                	jne    140002579 <__mingw_SEH_error_handler+0x169>
   14000255e:	ba 01 00 00 00       	mov    edx,0x1
   140002563:	b9 0b 00 00 00       	mov    ecx,0xb
   140002568:	e8 c3 70 00 00       	call   140009630 <signal>
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
   1400025a5:	e8 86 70 00 00       	call   140009630 <signal>
   1400025aa:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400025ae:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400025b3:	75 1b                	jne    1400025d0 <__mingw_SEH_error_handler+0x1c0>
   1400025b5:	ba 01 00 00 00       	mov    edx,0x1
   1400025ba:	b9 04 00 00 00       	mov    ecx,0x4
   1400025bf:	e8 6c 70 00 00       	call   140009630 <signal>
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
   140002600:	e8 2b 70 00 00       	call   140009630 <signal>
   140002605:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002609:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000260e:	75 23                	jne    140002633 <__mingw_SEH_error_handler+0x223>
   140002610:	ba 01 00 00 00       	mov    edx,0x1
   140002615:	b9 08 00 00 00       	mov    ecx,0x8
   14000261a:	e8 11 70 00 00       	call   140009630 <signal>
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
   14000278d:	e8 9e 6e 00 00       	call   140009630 <signal>
   140002792:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002796:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000279b:	75 1b                	jne    1400027b8 <_gnu_exception_handler+0x14e>
   14000279d:	ba 01 00 00 00       	mov    edx,0x1
   1400027a2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400027a7:	e8 84 6e 00 00       	call   140009630 <signal>
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
   1400027e4:	e8 47 6e 00 00       	call   140009630 <signal>
   1400027e9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400027ed:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400027f2:	75 1b                	jne    14000280f <_gnu_exception_handler+0x1a5>
   1400027f4:	ba 01 00 00 00       	mov    edx,0x1
   1400027f9:	b9 04 00 00 00       	mov    ecx,0x4
   1400027fe:	e8 2d 6e 00 00       	call   140009630 <signal>
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
   14000283f:	e8 ec 6d 00 00       	call   140009630 <signal>
   140002844:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002848:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000284d:	75 23                	jne    140002872 <_gnu_exception_handler+0x208>
   14000284f:	ba 01 00 00 00       	mov    edx,0x1
   140002854:	b9 08 00 00 00       	mov    ecx,0x8
   140002859:	e8 d2 6d 00 00       	call   140009630 <signal>
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
   1400028fa:	e8 d9 6c 00 00       	call   1400095d8 <calloc>
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
   140002930:	48 8b 05 c1 d8 00 00 	mov    rax,QWORD PTR [rip+0xd8c1]        # 1400101f8 <__imp_EnterCriticalSection>
   140002937:	ff d0                	call   rax
   140002939:	48 8b 15 10 c8 00 00 	mov    rdx,QWORD PTR [rip+0xc810]        # 14000f150 <key_dtor_list>
   140002940:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002944:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002948:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000294c:	48 89 05 fd c7 00 00 	mov    QWORD PTR [rip+0xc7fd],rax        # 14000f150 <key_dtor_list>
   140002953:	48 8d 05 c6 c7 00 00 	lea    rax,[rip+0xc7c6]        # 14000f120 <__mingwthr_cs>
   14000295a:	48 89 c1             	mov    rcx,rax
   14000295d:	48 8b 05 cc d8 00 00 	mov    rax,QWORD PTR [rip+0xd8cc]        # 140010230 <__imp_LeaveCriticalSection>
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
   14000299a:	48 8b 05 57 d8 00 00 	mov    rax,QWORD PTR [rip+0xd857]        # 1400101f8 <__imp_EnterCriticalSection>
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
   1400029f2:	e8 11 6c 00 00       	call   140009608 <free>
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
   140002a1e:	48 8b 05 0b d8 00 00 	mov    rax,QWORD PTR [rip+0xd80b]        # 140010230 <__imp_LeaveCriticalSection>
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
   140002a52:	48 8b 05 9f d7 00 00 	mov    rax,QWORD PTR [rip+0xd79f]        # 1400101f8 <__imp_EnterCriticalSection>
   140002a59:	ff d0                	call   rax
   140002a5b:	48 8b 05 ee c6 00 00 	mov    rax,QWORD PTR [rip+0xc6ee]        # 14000f150 <key_dtor_list>
   140002a62:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a66:	eb 46                	jmp    140002aae <__mingwthr_run_key_dtors+0x7c>
   140002a68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a6c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002a6e:	89 c1                	mov    ecx,eax
   140002a70:	48 8b 05 e1 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7e1]        # 140010258 <__imp_TlsGetValue>
   140002a77:	ff d0                	call   rax
   140002a79:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002a7d:	48 8b 05 8c d7 00 00 	mov    rax,QWORD PTR [rip+0xd78c]        # 140010210 <__imp_GetLastError>
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
   140002abf:	48 8b 05 6a d7 00 00 	mov    rax,QWORD PTR [rip+0xd76a]        # 140010230 <__imp_LeaveCriticalSection>
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
   140002b30:	48 8b 05 f1 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6f1]        # 140010228 <__imp_InitializeCriticalSection>
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
   140002b75:	e8 8e 6a 00 00       	call   140009608 <free>
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
   140002ba8:	48 8b 05 41 d6 00 00 	mov    rax,QWORD PTR [rip+0xd641]        # 1400101f0 <__IAT_start__>
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
   140002d08:	e8 33 69 00 00       	call   140009640 <strlen>
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
   140002d88:	e8 bb 68 00 00       	call   140009648 <strncmp>
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

00000001400030d0 <__mingw_printf>:
   1400030d0:	55                   	push   rbp
   1400030d1:	53                   	push   rbx
   1400030d2:	48 83 ec 48          	sub    rsp,0x48
   1400030d6:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   1400030db:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400030df:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400030e3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400030e7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   1400030eb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   1400030ef:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400030f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400030f8:	e8 c3 5e 00 00       	call   140008fc0 <__acrt_iob_func>
   1400030fd:	48 89 c1             	mov    rcx,rax
   140003100:	e8 3b 5d 00 00       	call   140008e40 <_lock_file>
   140003105:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140003109:	b9 01 00 00 00       	mov    ecx,0x1
   14000310e:	e8 ad 5e 00 00       	call   140008fc0 <__acrt_iob_func>
   140003113:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003117:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   14000311c:	49 89 d1             	mov    r9,rdx
   14000311f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003125:	48 89 c2             	mov    rdx,rax
   140003128:	b9 00 60 00 00       	mov    ecx,0x6000
   14000312d:	e8 b1 1f 00 00       	call   1400050e3 <__mingw_pformat>
   140003132:	89 c3                	mov    ebx,eax
   140003134:	b9 01 00 00 00       	mov    ecx,0x1
   140003139:	e8 82 5e 00 00       	call   140008fc0 <__acrt_iob_func>
   14000313e:	48 89 c1             	mov    rcx,rax
   140003141:	e8 84 5d 00 00       	call   140008eca <_unlock_file>
   140003146:	89 d8                	mov    eax,ebx
   140003148:	48 83 c4 48          	add    rsp,0x48
   14000314c:	5b                   	pop    rbx
   14000314d:	5d                   	pop    rbp
   14000314e:	c3                   	ret
   14000314f:	90                   	nop

0000000140003150 <__pformat_putc>:
   140003150:	55                   	push   rbp
   140003151:	48 89 e5             	mov    rbp,rsp
   140003154:	48 83 ec 20          	sub    rsp,0x20
   140003158:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000315b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000315f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003163:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003166:	25 00 40 00 00       	and    eax,0x4000
   14000316b:	85 c0                	test   eax,eax
   14000316d:	75 12                	jne    140003181 <__pformat_putc+0x31>
   14000316f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003173:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003176:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000317a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000317d:	39 c2                	cmp    edx,eax
   14000317f:	7e 3b                	jle    1400031bc <__pformat_putc+0x6c>
   140003181:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003185:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003188:	25 00 20 00 00       	and    eax,0x2000
   14000318d:	85 c0                	test   eax,eax
   14000318f:	74 13                	je     1400031a4 <__pformat_putc+0x54>
   140003191:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003195:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003198:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000319b:	89 c1                	mov    ecx,eax
   14000319d:	e8 5e 64 00 00       	call   140009600 <fputc>
   1400031a2:	eb 18                	jmp    1400031bc <__pformat_putc+0x6c>
   1400031a4:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031a8:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400031ab:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031af:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031b2:	48 98                	cdqe
   1400031b4:	48 01 d0             	add    rax,rdx
   1400031b7:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400031ba:	88 10                	mov    BYTE PTR [rax],dl
   1400031bc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031c0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400031c3:	8d 50 01             	lea    edx,[rax+0x1]
   1400031c6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400031ca:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400031cd:	90                   	nop
   1400031ce:	48 83 c4 20          	add    rsp,0x20
   1400031d2:	5d                   	pop    rbp
   1400031d3:	c3                   	ret

00000001400031d4 <__pformat_putchars>:
   1400031d4:	55                   	push   rbp
   1400031d5:	48 89 e5             	mov    rbp,rsp
   1400031d8:	48 83 ec 20          	sub    rsp,0x20
   1400031dc:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400031e0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400031e3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400031e7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031eb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400031ee:	85 c0                	test   eax,eax
   1400031f0:	78 16                	js     140003208 <__pformat_putchars+0x34>
   1400031f2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400031f6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400031f9:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400031fc:	7e 0a                	jle    140003208 <__pformat_putchars+0x34>
   1400031fe:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003202:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003205:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003208:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000320c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000320f:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003212:	7d 15                	jge    140003229 <__pformat_putchars+0x55>
   140003214:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003218:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000321b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000321e:	89 c2                	mov    edx,eax
   140003220:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003224:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003227:	eb 0b                	jmp    140003234 <__pformat_putchars+0x60>
   140003229:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000322d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003234:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003238:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000323b:	85 c0                	test   eax,eax
   14000323d:	7e 57                	jle    140003296 <__pformat_putchars+0xc2>
   14000323f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003243:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003246:	25 00 04 00 00       	and    eax,0x400
   14000324b:	85 c0                	test   eax,eax
   14000324d:	75 47                	jne    140003296 <__pformat_putchars+0xc2>
   14000324f:	eb 11                	jmp    140003262 <__pformat_putchars+0x8e>
   140003251:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003255:	48 89 c2             	mov    rdx,rax
   140003258:	b9 20 00 00 00       	mov    ecx,0x20
   14000325d:	e8 ee fe ff ff       	call   140003150 <__pformat_putc>
   140003262:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003266:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003269:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000326c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003270:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003273:	85 c0                	test   eax,eax
   140003275:	75 da                	jne    140003251 <__pformat_putchars+0x7d>
   140003277:	eb 1d                	jmp    140003296 <__pformat_putchars+0xc2>
   140003279:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000327d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003281:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003285:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003288:	0f be c0             	movsx  eax,al
   14000328b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000328f:	89 c1                	mov    ecx,eax
   140003291:	e8 ba fe ff ff       	call   140003150 <__pformat_putc>
   140003296:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003299:	8d 50 ff             	lea    edx,[rax-0x1]
   14000329c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000329f:	85 c0                	test   eax,eax
   1400032a1:	75 d6                	jne    140003279 <__pformat_putchars+0xa5>
   1400032a3:	eb 11                	jmp    1400032b6 <__pformat_putchars+0xe2>
   1400032a5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032a9:	48 89 c2             	mov    rdx,rax
   1400032ac:	b9 20 00 00 00       	mov    ecx,0x20
   1400032b1:	e8 9a fe ff ff       	call   140003150 <__pformat_putc>
   1400032b6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032ba:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400032bd:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400032c0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400032c4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400032c7:	85 c0                	test   eax,eax
   1400032c9:	7f da                	jg     1400032a5 <__pformat_putchars+0xd1>
   1400032cb:	90                   	nop
   1400032cc:	90                   	nop
   1400032cd:	48 83 c4 20          	add    rsp,0x20
   1400032d1:	5d                   	pop    rbp
   1400032d2:	c3                   	ret

00000001400032d3 <__pformat_puts>:
   1400032d3:	55                   	push   rbp
   1400032d4:	48 89 e5             	mov    rbp,rsp
   1400032d7:	48 83 ec 20          	sub    rsp,0x20
   1400032db:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032df:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400032e3:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400032e8:	75 0b                	jne    1400032f5 <__pformat_puts+0x22>
   1400032ea:	48 8d 05 3f 80 00 00 	lea    rax,[rip+0x803f]        # 14000b330 <.rdata>
   1400032f1:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400032f5:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032f9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032fc:	85 c0                	test   eax,eax
   1400032fe:	78 2f                	js     14000332f <__pformat_puts+0x5c>
   140003300:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003304:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003307:	48 63 d0             	movsxd rdx,eax
   14000330a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000330e:	48 89 c1             	mov    rcx,rax
   140003311:	e8 4a 5a 00 00       	call   140008d60 <strnlen>
   140003316:	89 c1                	mov    ecx,eax
   140003318:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000331c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003320:	49 89 d0             	mov    r8,rdx
   140003323:	89 ca                	mov    edx,ecx
   140003325:	48 89 c1             	mov    rcx,rax
   140003328:	e8 a7 fe ff ff       	call   1400031d4 <__pformat_putchars>
   14000332d:	eb 23                	jmp    140003352 <__pformat_puts+0x7f>
   14000332f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003333:	48 89 c1             	mov    rcx,rax
   140003336:	e8 05 63 00 00       	call   140009640 <strlen>
   14000333b:	89 c1                	mov    ecx,eax
   14000333d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003341:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003345:	49 89 d0             	mov    r8,rdx
   140003348:	89 ca                	mov    edx,ecx
   14000334a:	48 89 c1             	mov    rcx,rax
   14000334d:	e8 82 fe ff ff       	call   1400031d4 <__pformat_putchars>
   140003352:	90                   	nop
   140003353:	48 83 c4 20          	add    rsp,0x20
   140003357:	5d                   	pop    rbp
   140003358:	c3                   	ret

0000000140003359 <__pformat_wputchars>:
   140003359:	55                   	push   rbp
   14000335a:	48 89 e5             	mov    rbp,rsp
   14000335d:	48 83 ec 50          	sub    rsp,0x50
   140003361:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003365:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003368:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000336c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003373:	00 
   140003374:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003378:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000337b:	85 c0                	test   eax,eax
   14000337d:	78 16                	js     140003395 <__pformat_wputchars+0x3c>
   14000337f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003383:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003386:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003389:	7e 0a                	jle    140003395 <__pformat_wputchars+0x3c>
   14000338b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000338f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003392:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003395:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003399:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000339c:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000339f:	7d 15                	jge    1400033b6 <__pformat_wputchars+0x5d>
   1400033a1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033a5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033a8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400033ab:	89 c2                	mov    edx,eax
   1400033ad:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033b1:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400033b4:	eb 0b                	jmp    1400033c1 <__pformat_wputchars+0x68>
   1400033b6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033ba:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400033c1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033c5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033c8:	85 c0                	test   eax,eax
   1400033ca:	7e 6e                	jle    14000343a <__pformat_wputchars+0xe1>
   1400033cc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033d0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400033d3:	25 00 04 00 00       	and    eax,0x400
   1400033d8:	85 c0                	test   eax,eax
   1400033da:	75 5e                	jne    14000343a <__pformat_wputchars+0xe1>
   1400033dc:	eb 11                	jmp    1400033ef <__pformat_wputchars+0x96>
   1400033de:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033e2:	48 89 c2             	mov    rdx,rax
   1400033e5:	b9 20 00 00 00       	mov    ecx,0x20
   1400033ea:	e8 61 fd ff ff       	call   140003150 <__pformat_putc>
   1400033ef:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033f3:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033f6:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400033f9:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400033fd:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003400:	85 c0                	test   eax,eax
   140003402:	75 da                	jne    1400033de <__pformat_wputchars+0x85>
   140003404:	eb 34                	jmp    14000343a <__pformat_wputchars+0xe1>
   140003406:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000340a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000340e:	eb 1d                	jmp    14000342d <__pformat_wputchars+0xd4>
   140003410:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003414:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003418:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000341c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000341f:	0f be c0             	movsx  eax,al
   140003422:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003426:	89 c1                	mov    ecx,eax
   140003428:	e8 23 fd ff ff       	call   140003150 <__pformat_putc>
   14000342d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003430:	8d 50 ff             	lea    edx,[rax-0x1]
   140003433:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003436:	85 c0                	test   eax,eax
   140003438:	7f d6                	jg     140003410 <__pformat_wputchars+0xb7>
   14000343a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000343d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003440:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003443:	85 c0                	test   eax,eax
   140003445:	7e 41                	jle    140003488 <__pformat_wputchars+0x12f>
   140003447:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000344b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000344f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003453:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003456:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000345a:	0f b7 d0             	movzx  edx,ax
   14000345d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003461:	49 89 c8             	mov    r8,rcx
   140003464:	48 89 c1             	mov    rcx,rax
   140003467:	e8 84 5b 00 00       	call   140008ff0 <wcrtomb>
   14000346c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000346f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003473:	7f 91                	jg     140003406 <__pformat_wputchars+0xad>
   140003475:	eb 11                	jmp    140003488 <__pformat_wputchars+0x12f>
   140003477:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000347b:	48 89 c2             	mov    rdx,rax
   14000347e:	b9 20 00 00 00       	mov    ecx,0x20
   140003483:	e8 c8 fc ff ff       	call   140003150 <__pformat_putc>
   140003488:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000348c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000348f:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003492:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003496:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003499:	85 c0                	test   eax,eax
   14000349b:	7f da                	jg     140003477 <__pformat_wputchars+0x11e>
   14000349d:	90                   	nop
   14000349e:	90                   	nop
   14000349f:	48 83 c4 50          	add    rsp,0x50
   1400034a3:	5d                   	pop    rbp
   1400034a4:	c3                   	ret

00000001400034a5 <__pformat_wcputs>:
   1400034a5:	55                   	push   rbp
   1400034a6:	48 89 e5             	mov    rbp,rsp
   1400034a9:	48 83 ec 20          	sub    rsp,0x20
   1400034ad:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400034b1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400034b5:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400034ba:	75 0b                	jne    1400034c7 <__pformat_wcputs+0x22>
   1400034bc:	48 8d 05 75 7e 00 00 	lea    rax,[rip+0x7e75]        # 14000b338 <.rdata+0x8>
   1400034c3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400034c7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400034cb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034ce:	85 c0                	test   eax,eax
   1400034d0:	78 2f                	js     140003501 <__pformat_wcputs+0x5c>
   1400034d2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400034d6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034d9:	48 63 d0             	movsxd rdx,eax
   1400034dc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034e0:	48 89 c1             	mov    rcx,rax
   1400034e3:	e8 28 58 00 00       	call   140008d10 <wcsnlen>
   1400034e8:	89 c1                	mov    ecx,eax
   1400034ea:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400034ee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400034f2:	49 89 d0             	mov    r8,rdx
   1400034f5:	89 ca                	mov    edx,ecx
   1400034f7:	48 89 c1             	mov    rcx,rax
   1400034fa:	e8 5a fe ff ff       	call   140003359 <__pformat_wputchars>
   1400034ff:	eb 23                	jmp    140003524 <__pformat_wcputs+0x7f>
   140003501:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003505:	48 89 c1             	mov    rcx,rax
   140003508:	e8 4b 61 00 00       	call   140009658 <wcslen>
   14000350d:	89 c1                	mov    ecx,eax
   14000350f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003513:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003517:	49 89 d0             	mov    r8,rdx
   14000351a:	89 ca                	mov    edx,ecx
   14000351c:	48 89 c1             	mov    rcx,rax
   14000351f:	e8 35 fe ff ff       	call   140003359 <__pformat_wputchars>
   140003524:	90                   	nop
   140003525:	48 83 c4 20          	add    rsp,0x20
   140003529:	5d                   	pop    rbp
   14000352a:	c3                   	ret

000000014000352b <__pformat_int_bufsiz>:
   14000352b:	55                   	push   rbp
   14000352c:	48 89 e5             	mov    rbp,rsp
   14000352f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003532:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003535:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003539:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000353c:	83 e8 01             	sub    eax,0x1
   14000353f:	48 98                	cdqe
   140003541:	48 83 c0 40          	add    rax,0x40
   140003545:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003548:	48 63 ca             	movsxd rcx,edx
   14000354b:	ba 00 00 00 00       	mov    edx,0x0
   140003550:	48 f7 f1             	div    rcx
   140003553:	89 c2                	mov    edx,eax
   140003555:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003558:	01 d0                	add    eax,edx
   14000355a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000355d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003561:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003564:	ba 00 00 00 00       	mov    edx,0x0
   140003569:	85 c0                	test   eax,eax
   14000356b:	0f 48 c2             	cmovs  eax,edx
   14000356e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003571:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003575:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003578:	25 00 10 00 00       	and    eax,0x1000
   14000357d:	85 c0                	test   eax,eax
   14000357f:	74 29                	je     1400035aa <__pformat_int_bufsiz+0x7f>
   140003581:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003585:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003589:	66 85 c0             	test   ax,ax
   14000358c:	74 1c                	je     1400035aa <__pformat_int_bufsiz+0x7f>
   14000358e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140003591:	48 63 d0             	movsxd rdx,eax
   140003594:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   14000359b:	48 89 d1             	mov    rcx,rdx
   14000359e:	48 c1 e9 20          	shr    rcx,0x20
   1400035a2:	99                   	cdq
   1400035a3:	89 c8                	mov    eax,ecx
   1400035a5:	29 d0                	sub    eax,edx
   1400035a7:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400035aa:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400035ae:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400035b1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400035b4:	39 c2                	cmp    edx,eax
   1400035b6:	0f 4d c2             	cmovge eax,edx
   1400035b9:	5d                   	pop    rbp
   1400035ba:	c3                   	ret

00000001400035bb <__pformat_int>:
   1400035bb:	55                   	push   rbp
   1400035bc:	53                   	push   rbx
   1400035bd:	48 83 ec 58          	sub    rsp,0x58
   1400035c1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400035c6:	48 89 cb             	mov    rbx,rcx
   1400035c9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400035cc:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   1400035d0:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   1400035d4:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   1400035d8:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400035dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400035e0:	49 89 c0             	mov    r8,rax
   1400035e3:	ba 03 00 00 00       	mov    edx,0x3
   1400035e8:	b9 01 00 00 00       	mov    ecx,0x1
   1400035ed:	e8 39 ff ff ff       	call   14000352b <__pformat_int_bufsiz>
   1400035f2:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400035f5:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   1400035fc:	00 
   1400035fd:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140003600:	48 98                	cdqe
   140003602:	48 83 c0 0f          	add    rax,0xf
   140003606:	48 c1 e8 04          	shr    rax,0x4
   14000360a:	48 c1 e0 04          	shl    rax,0x4
   14000360e:	e8 7d fa ff ff       	call   140003090 <___chkstk_ms>
   140003613:	48 29 c4             	sub    rsp,rax
   140003616:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000361b:	48 83 c0 0f          	add    rax,0xf
   14000361f:	48 c1 e8 04          	shr    rax,0x4
   140003623:	48 c1 e0 04          	shl    rax,0x4
   140003627:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000362b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000362f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003633:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003637:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000363a:	25 80 00 00 00       	and    eax,0x80
   14000363f:	85 c0                	test   eax,eax
   140003641:	0f 84 ea 00 00 00    	je     140003731 <__pformat_int+0x176>
   140003647:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000364b:	48 85 c0             	test   rax,rax
   14000364e:	79 10                	jns    140003660 <__pformat_int+0xa5>
   140003650:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003654:	48 f7 d8             	neg    rax
   140003657:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000365b:	e9 d1 00 00 00       	jmp    140003731 <__pformat_int+0x176>
   140003660:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003664:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003667:	24 7f                	and    al,0x7f
   140003669:	89 c2                	mov    edx,eax
   14000366b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000366f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003672:	e9 ba 00 00 00       	jmp    140003731 <__pformat_int+0x176>
   140003677:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000367b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000367f:	74 54                	je     1400036d5 <__pformat_int+0x11a>
   140003681:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003685:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003688:	25 00 10 00 00       	and    eax,0x1000
   14000368d:	85 c0                	test   eax,eax
   14000368f:	74 44                	je     1400036d5 <__pformat_int+0x11a>
   140003691:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003695:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003699:	66 85 c0             	test   ax,ax
   14000369c:	74 37                	je     1400036d5 <__pformat_int+0x11a>
   14000369e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036a2:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400036a6:	48 89 c2             	mov    rdx,rax
   1400036a9:	48 89 d0             	mov    rax,rdx
   1400036ac:	48 c1 f8 3f          	sar    rax,0x3f
   1400036b0:	48 c1 e8 3e          	shr    rax,0x3e
   1400036b4:	48 01 c2             	add    rdx,rax
   1400036b7:	83 e2 03             	and    edx,0x3
   1400036ba:	48 29 c2             	sub    rdx,rax
   1400036bd:	48 89 d0             	mov    rax,rdx
   1400036c0:	48 83 f8 03          	cmp    rax,0x3
   1400036c4:	75 0f                	jne    1400036d5 <__pformat_int+0x11a>
   1400036c6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400036ca:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400036ce:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400036d2:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   1400036d5:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   1400036d9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400036e0:	cc cc cc 
   1400036e3:	48 89 c8             	mov    rax,rcx
   1400036e6:	48 f7 e2             	mul    rdx
   1400036e9:	48 c1 ea 03          	shr    rdx,0x3
   1400036ed:	48 89 d0             	mov    rax,rdx
   1400036f0:	48 c1 e0 02          	shl    rax,0x2
   1400036f4:	48 01 d0             	add    rax,rdx
   1400036f7:	48 01 c0             	add    rax,rax
   1400036fa:	48 29 c1             	sub    rcx,rax
   1400036fd:	48 89 ca             	mov    rdx,rcx
   140003700:	89 d0                	mov    eax,edx
   140003702:	8d 48 30             	lea    ecx,[rax+0x30]
   140003705:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003709:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000370d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003711:	89 ca                	mov    edx,ecx
   140003713:	88 10                	mov    BYTE PTR [rax],dl
   140003715:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003719:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003720:	cc cc cc 
   140003723:	48 f7 e2             	mul    rdx
   140003726:	48 89 d0             	mov    rax,rdx
   140003729:	48 c1 e8 03          	shr    rax,0x3
   14000372d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003731:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003735:	48 85 c0             	test   rax,rax
   140003738:	0f 85 39 ff ff ff    	jne    140003677 <__pformat_int+0xbc>
   14000373e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003742:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003745:	85 c0                	test   eax,eax
   140003747:	7e 3e                	jle    140003787 <__pformat_int+0x1cc>
   140003749:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000374d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003750:	89 c1                	mov    ecx,eax
   140003752:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003756:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000375a:	89 c2                	mov    edx,eax
   14000375c:	89 c8                	mov    eax,ecx
   14000375e:	29 d0                	sub    eax,edx
   140003760:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003763:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003767:	7e 1e                	jle    140003787 <__pformat_int+0x1cc>
   140003769:	eb 0f                	jmp    14000377a <__pformat_int+0x1bf>
   14000376b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000376f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003773:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003777:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000377a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000377d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003780:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003783:	85 c0                	test   eax,eax
   140003785:	7f e4                	jg     14000376b <__pformat_int+0x1b0>
   140003787:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000378b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000378f:	75 1a                	jne    1400037ab <__pformat_int+0x1f0>
   140003791:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003795:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003798:	85 c0                	test   eax,eax
   14000379a:	74 0f                	je     1400037ab <__pformat_int+0x1f0>
   14000379c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037a0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037a4:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037a8:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400037ab:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037af:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037b2:	85 c0                	test   eax,eax
   1400037b4:	0f 8e ce 00 00 00    	jle    140003888 <__pformat_int+0x2cd>
   1400037ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037be:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037c1:	89 c1                	mov    ecx,eax
   1400037c3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037c7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037cb:	89 c2                	mov    edx,eax
   1400037cd:	89 c8                	mov    eax,ecx
   1400037cf:	29 d0                	sub    eax,edx
   1400037d1:	89 c2                	mov    edx,eax
   1400037d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037d7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400037da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037de:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400037e1:	85 c0                	test   eax,eax
   1400037e3:	0f 8e 9f 00 00 00    	jle    140003888 <__pformat_int+0x2cd>
   1400037e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037ed:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400037f0:	25 c0 01 00 00       	and    eax,0x1c0
   1400037f5:	85 c0                	test   eax,eax
   1400037f7:	74 11                	je     14000380a <__pformat_int+0x24f>
   1400037f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037fd:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003800:	8d 50 ff             	lea    edx,[rax-0x1]
   140003803:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003807:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000380a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000380e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003811:	85 c0                	test   eax,eax
   140003813:	79 3b                	jns    140003850 <__pformat_int+0x295>
   140003815:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003819:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000381c:	25 00 06 00 00       	and    eax,0x600
   140003821:	3d 00 02 00 00       	cmp    eax,0x200
   140003826:	75 28                	jne    140003850 <__pformat_int+0x295>
   140003828:	eb 0f                	jmp    140003839 <__pformat_int+0x27e>
   14000382a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000382e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003832:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003836:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003839:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000383d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003840:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003843:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003847:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000384a:	85 c0                	test   eax,eax
   14000384c:	7f dc                	jg     14000382a <__pformat_int+0x26f>
   14000384e:	eb 38                	jmp    140003888 <__pformat_int+0x2cd>
   140003850:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003854:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003857:	25 00 04 00 00       	and    eax,0x400
   14000385c:	85 c0                	test   eax,eax
   14000385e:	75 28                	jne    140003888 <__pformat_int+0x2cd>
   140003860:	eb 11                	jmp    140003873 <__pformat_int+0x2b8>
   140003862:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003866:	48 89 c2             	mov    rdx,rax
   140003869:	b9 20 00 00 00       	mov    ecx,0x20
   14000386e:	e8 dd f8 ff ff       	call   140003150 <__pformat_putc>
   140003873:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003877:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000387a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000387d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003881:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003884:	85 c0                	test   eax,eax
   140003886:	7f da                	jg     140003862 <__pformat_int+0x2a7>
   140003888:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000388c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000388f:	25 80 00 00 00       	and    eax,0x80
   140003894:	85 c0                	test   eax,eax
   140003896:	74 11                	je     1400038a9 <__pformat_int+0x2ee>
   140003898:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000389c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038a0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038a4:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400038a7:	eb 5a                	jmp    140003903 <__pformat_int+0x348>
   1400038a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ad:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038b0:	25 00 01 00 00       	and    eax,0x100
   1400038b5:	85 c0                	test   eax,eax
   1400038b7:	74 11                	je     1400038ca <__pformat_int+0x30f>
   1400038b9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038bd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038c1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038c5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400038c8:	eb 39                	jmp    140003903 <__pformat_int+0x348>
   1400038ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400038d1:	83 e0 40             	and    eax,0x40
   1400038d4:	85 c0                	test   eax,eax
   1400038d6:	74 2b                	je     140003903 <__pformat_int+0x348>
   1400038d8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038dc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038e0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038e4:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400038e7:	eb 1a                	jmp    140003903 <__pformat_int+0x348>
   1400038e9:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   1400038ee:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038f2:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400038f5:	0f be c0             	movsx  eax,al
   1400038f8:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400038fc:	89 c1                	mov    ecx,eax
   1400038fe:	e8 4d f8 ff ff       	call   140003150 <__pformat_putc>
   140003903:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003907:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   14000390b:	72 dc                	jb     1400038e9 <__pformat_int+0x32e>
   14000390d:	eb 11                	jmp    140003920 <__pformat_int+0x365>
   14000390f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003913:	48 89 c2             	mov    rdx,rax
   140003916:	b9 20 00 00 00       	mov    ecx,0x20
   14000391b:	e8 30 f8 ff ff       	call   140003150 <__pformat_putc>
   140003920:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003924:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003927:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000392a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000392e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003931:	85 c0                	test   eax,eax
   140003933:	7f da                	jg     14000390f <__pformat_int+0x354>
   140003935:	90                   	nop
   140003936:	90                   	nop
   140003937:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   14000393b:	5b                   	pop    rbx
   14000393c:	5d                   	pop    rbp
   14000393d:	c3                   	ret

000000014000393e <__pformat_xint>:
   14000393e:	55                   	push   rbp
   14000393f:	53                   	push   rbx
   140003940:	48 83 ec 68          	sub    rsp,0x68
   140003944:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003949:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   14000394c:	48 89 d3             	mov    rbx,rdx
   14000394f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003952:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003956:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   14000395a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   14000395e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003962:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003966:	74 1e                	je     140003986 <__pformat_xint+0x48>
   140003968:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   14000396c:	74 06                	je     140003974 <__pformat_xint+0x36>
   14000396e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003972:	75 09                	jne    14000397d <__pformat_xint+0x3f>
   140003974:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000397b:	eb 10                	jmp    14000398d <__pformat_xint+0x4f>
   14000397d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003984:	eb 07                	jmp    14000398d <__pformat_xint+0x4f>
   140003986:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   14000398d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003991:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003994:	49 89 d0             	mov    r8,rdx
   140003997:	89 c2                	mov    edx,eax
   140003999:	b9 02 00 00 00       	mov    ecx,0x2
   14000399e:	e8 88 fb ff ff       	call   14000352b <__pformat_int_bufsiz>
   1400039a3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400039a6:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   1400039ad:	00 
   1400039ae:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400039b1:	48 98                	cdqe
   1400039b3:	48 83 c0 0f          	add    rax,0xf
   1400039b7:	48 c1 e8 04          	shr    rax,0x4
   1400039bb:	48 c1 e0 04          	shl    rax,0x4
   1400039bf:	e8 cc f6 ff ff       	call   140003090 <___chkstk_ms>
   1400039c4:	48 29 c4             	sub    rsp,rax
   1400039c7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   1400039cc:	48 83 c0 0f          	add    rax,0xf
   1400039d0:	48 c1 e8 04          	shr    rax,0x4
   1400039d4:	48 c1 e0 04          	shl    rax,0x4
   1400039d8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400039dc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400039e0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400039e4:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   1400039e8:	74 1e                	je     140003a08 <__pformat_xint+0xca>
   1400039ea:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   1400039ee:	74 06                	je     1400039f6 <__pformat_xint+0xb8>
   1400039f0:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   1400039f4:	75 09                	jne    1400039ff <__pformat_xint+0xc1>
   1400039f6:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   1400039fd:	eb 10                	jmp    140003a0f <__pformat_xint+0xd1>
   1400039ff:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003a06:	eb 67                	jmp    140003a6f <__pformat_xint+0x131>
   140003a08:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003a0f:	eb 5e                	jmp    140003a6f <__pformat_xint+0x131>
   140003a11:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a15:	89 c2                	mov    edx,eax
   140003a17:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003a1a:	21 d0                	and    eax,edx
   140003a1c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003a1f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a23:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003a27:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003a2b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003a2f:	89 ca                	mov    edx,ecx
   140003a31:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a35:	88 10                	mov    BYTE PTR [rax],dl
   140003a37:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a3b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a3e:	3c 39                	cmp    al,0x39
   140003a40:	7e 1a                	jle    140003a5c <__pformat_xint+0x11e>
   140003a42:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a46:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a49:	83 c0 07             	add    eax,0x7
   140003a4c:	89 c2                	mov    edx,eax
   140003a4e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003a51:	83 e0 20             	and    eax,0x20
   140003a54:	09 c2                	or     edx,eax
   140003a56:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003a5a:	88 10                	mov    BYTE PTR [rax],dl
   140003a5c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003a60:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003a63:	89 c1                	mov    ecx,eax
   140003a65:	48 d3 ea             	shr    rdx,cl
   140003a68:	48 89 d0             	mov    rax,rdx
   140003a6b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a6f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003a73:	48 85 c0             	test   rax,rax
   140003a76:	75 99                	jne    140003a11 <__pformat_xint+0xd3>
   140003a78:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003a7c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003a80:	75 13                	jne    140003a95 <__pformat_xint+0x157>
   140003a82:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003a86:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003a89:	80 e4 f7             	and    ah,0xf7
   140003a8c:	89 c2                	mov    edx,eax
   140003a8e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003a92:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003a95:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003a99:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003a9c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003a9f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003aa3:	7e 3a                	jle    140003adf <__pformat_xint+0x1a1>
   140003aa5:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003aa8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003aac:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003ab0:	89 c1                	mov    ecx,eax
   140003ab2:	89 d0                	mov    eax,edx
   140003ab4:	29 c8                	sub    eax,ecx
   140003ab6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003ab9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003abd:	7e 20                	jle    140003adf <__pformat_xint+0x1a1>
   140003abf:	eb 0f                	jmp    140003ad0 <__pformat_xint+0x192>
   140003ac1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003ac5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003ac9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003acd:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003ad0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ad3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003ad6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003ad9:	85 c0                	test   eax,eax
   140003adb:	7f e4                	jg     140003ac1 <__pformat_xint+0x183>
   140003add:	eb 25                	jmp    140003b04 <__pformat_xint+0x1c6>
   140003adf:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003ae3:	75 1f                	jne    140003b04 <__pformat_xint+0x1c6>
   140003ae5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ae9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003aec:	25 00 08 00 00       	and    eax,0x800
   140003af1:	85 c0                	test   eax,eax
   140003af3:	74 0f                	je     140003b04 <__pformat_xint+0x1c6>
   140003af5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003af9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003afd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b01:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b04:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b08:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b0c:	75 1a                	jne    140003b28 <__pformat_xint+0x1ea>
   140003b0e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b12:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b15:	85 c0                	test   eax,eax
   140003b17:	74 0f                	je     140003b28 <__pformat_xint+0x1ea>
   140003b19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b1d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b21:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b25:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003b28:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b2c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b2f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003b33:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003b37:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003b3a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003b3d:	7d 15                	jge    140003b54 <__pformat_xint+0x216>
   140003b3f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b43:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b46:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003b49:	89 c2                	mov    edx,eax
   140003b4b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b4f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003b52:	eb 0b                	jmp    140003b5f <__pformat_xint+0x221>
   140003b54:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b58:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003b5f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b63:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003b66:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003b69:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b6d:	7e 1a                	jle    140003b89 <__pformat_xint+0x24b>
   140003b6f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003b73:	74 14                	je     140003b89 <__pformat_xint+0x24b>
   140003b75:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b79:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b7c:	25 00 08 00 00       	and    eax,0x800
   140003b81:	85 c0                	test   eax,eax
   140003b83:	74 04                	je     140003b89 <__pformat_xint+0x24b>
   140003b85:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003b89:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003b8d:	7e 3c                	jle    140003bcb <__pformat_xint+0x28d>
   140003b8f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b93:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003b96:	85 c0                	test   eax,eax
   140003b98:	79 31                	jns    140003bcb <__pformat_xint+0x28d>
   140003b9a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b9e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003ba1:	25 00 06 00 00       	and    eax,0x600
   140003ba6:	3d 00 02 00 00       	cmp    eax,0x200
   140003bab:	75 1e                	jne    140003bcb <__pformat_xint+0x28d>
   140003bad:	eb 0f                	jmp    140003bbe <__pformat_xint+0x280>
   140003baf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bb3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bb7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bbb:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003bbe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003bc1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003bc4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003bc7:	85 c0                	test   eax,eax
   140003bc9:	7f e4                	jg     140003baf <__pformat_xint+0x271>
   140003bcb:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bcf:	74 30                	je     140003c01 <__pformat_xint+0x2c3>
   140003bd1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bd5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bd8:	25 00 08 00 00       	and    eax,0x800
   140003bdd:	85 c0                	test   eax,eax
   140003bdf:	74 20                	je     140003c01 <__pformat_xint+0x2c3>
   140003be1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003be5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003be9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bed:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003bf0:	88 10                	mov    BYTE PTR [rax],dl
   140003bf2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bf6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bfa:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bfe:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c01:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c05:	7e 4c                	jle    140003c53 <__pformat_xint+0x315>
   140003c07:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c0b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c0e:	25 00 04 00 00       	and    eax,0x400
   140003c13:	85 c0                	test   eax,eax
   140003c15:	75 3c                	jne    140003c53 <__pformat_xint+0x315>
   140003c17:	eb 11                	jmp    140003c2a <__pformat_xint+0x2ec>
   140003c19:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c1d:	48 89 c2             	mov    rdx,rax
   140003c20:	b9 20 00 00 00       	mov    ecx,0x20
   140003c25:	e8 26 f5 ff ff       	call   140003150 <__pformat_putc>
   140003c2a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c2d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c30:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c33:	85 c0                	test   eax,eax
   140003c35:	7f e2                	jg     140003c19 <__pformat_xint+0x2db>
   140003c37:	eb 1a                	jmp    140003c53 <__pformat_xint+0x315>
   140003c39:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003c3e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c42:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003c45:	0f be c0             	movsx  eax,al
   140003c48:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003c4c:	89 c1                	mov    ecx,eax
   140003c4e:	e8 fd f4 ff ff       	call   140003150 <__pformat_putc>
   140003c53:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c57:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003c5b:	72 dc                	jb     140003c39 <__pformat_xint+0x2fb>
   140003c5d:	eb 11                	jmp    140003c70 <__pformat_xint+0x332>
   140003c5f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c63:	48 89 c2             	mov    rdx,rax
   140003c66:	b9 20 00 00 00       	mov    ecx,0x20
   140003c6b:	e8 e0 f4 ff ff       	call   140003150 <__pformat_putc>
   140003c70:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003c73:	8d 50 ff             	lea    edx,[rax-0x1]
   140003c76:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c79:	85 c0                	test   eax,eax
   140003c7b:	7f e2                	jg     140003c5f <__pformat_xint+0x321>
   140003c7d:	90                   	nop
   140003c7e:	90                   	nop
   140003c7f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003c83:	5b                   	pop    rbx
   140003c84:	5d                   	pop    rbp
   140003c85:	c3                   	ret

0000000140003c86 <init_fpreg_ldouble>:
   140003c86:	55                   	push   rbp
   140003c87:	53                   	push   rbx
   140003c88:	48 83 ec 28          	sub    rsp,0x28
   140003c8c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003c91:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003c95:	48 89 d3             	mov    rbx,rdx
   140003c98:	db 2b                	fld    TBYTE PTR [rbx]
   140003c9a:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003c9d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003ca0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003ca3:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003ca7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cab:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003caf:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003cb2:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003cb6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003cba:	48 83 c4 28          	add    rsp,0x28
   140003cbe:	5b                   	pop    rbx
   140003cbf:	5d                   	pop    rbp
   140003cc0:	c3                   	ret

0000000140003cc1 <__pformat_cvt>:
   140003cc1:	55                   	push   rbp
   140003cc2:	53                   	push   rbx
   140003cc3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003cca:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003cd1:	00 
   140003cd2:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003cd5:	48 89 d3             	mov    rbx,rdx
   140003cd8:	db 2b                	fld    TBYTE PTR [rbx]
   140003cda:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003cdd:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003ce1:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003ce5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003cec:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003cf0:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003cf3:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003cf6:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003cfa:	48 89 c1             	mov    rcx,rax
   140003cfd:	e8 84 ff ff ff       	call   140003c86 <init_fpreg_ldouble>
   140003d02:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003d05:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003d08:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003d0c:	48 89 c1             	mov    rcx,rax
   140003d0f:	e8 9c 4e 00 00       	call   140008bb0 <__fpclassifyl>
   140003d14:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d17:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d1a:	25 00 01 00 00       	and    eax,0x100
   140003d1f:	85 c0                	test   eax,eax
   140003d21:	74 1d                	je     140003d40 <__pformat_cvt+0x7f>
   140003d23:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d26:	25 00 04 00 00       	and    eax,0x400
   140003d2b:	85 c0                	test   eax,eax
   140003d2d:	74 07                	je     140003d36 <__pformat_cvt+0x75>
   140003d2f:	b8 03 00 00 00       	mov    eax,0x3
   140003d34:	eb 05                	jmp    140003d3b <__pformat_cvt+0x7a>
   140003d36:	b8 04 00 00 00       	mov    eax,0x4
   140003d3b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003d3e:	eb 4a                	jmp    140003d8a <__pformat_cvt+0xc9>
   140003d40:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d43:	25 00 04 00 00       	and    eax,0x400
   140003d48:	85 c0                	test   eax,eax
   140003d4a:	74 37                	je     140003d83 <__pformat_cvt+0xc2>
   140003d4c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d4f:	25 00 40 00 00       	and    eax,0x4000
   140003d54:	85 c0                	test   eax,eax
   140003d56:	74 10                	je     140003d68 <__pformat_cvt+0xa7>
   140003d58:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003d5f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003d66:	eb 22                	jmp    140003d8a <__pformat_cvt+0xc9>
   140003d68:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003d6f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003d73:	98                   	cwde
   140003d74:	25 ff 7f 00 00       	and    eax,0x7fff
   140003d79:	2d 3e 40 00 00       	sub    eax,0x403e
   140003d7e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003d81:	eb 07                	jmp    140003d8a <__pformat_cvt+0xc9>
   140003d83:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003d8a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003d8d:	83 f8 04             	cmp    eax,0x4
   140003d90:	74 0e                	je     140003da0 <__pformat_cvt+0xdf>
   140003d92:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003d96:	98                   	cwde
   140003d97:	25 00 80 00 00       	and    eax,0x8000
   140003d9c:	89 c2                	mov    edx,eax
   140003d9e:	eb 05                	jmp    140003da5 <__pformat_cvt+0xe4>
   140003da0:	ba 00 00 00 00       	mov    edx,0x0
   140003da5:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003da9:	89 10                	mov    DWORD PTR [rax],edx
   140003dab:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003dae:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003db2:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003db6:	48 8d 0d b3 62 00 00 	lea    rcx,[rip+0x62b3]        # 14000a070 <fpi.0>
   140003dbd:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003dc1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003dc6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003dca:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003dcf:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003dd2:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003dd6:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003dd9:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003ddd:	89 c2                	mov    edx,eax
   140003ddf:	e8 96 24 00 00       	call   14000627a <__gdtoa>
   140003de4:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003deb:	5b                   	pop    rbx
   140003dec:	5d                   	pop    rbp
   140003ded:	c3                   	ret

0000000140003dee <__pformat_ecvt>:
   140003dee:	55                   	push   rbp
   140003def:	53                   	push   rbx
   140003df0:	48 83 ec 58          	sub    rsp,0x58
   140003df4:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003df9:	48 89 cb             	mov    rbx,rcx
   140003dfc:	db 2b                	fld    TBYTE PTR [rbx]
   140003dfe:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e01:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e04:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e08:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e0c:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e0f:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e12:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e16:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e19:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e1d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e21:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e26:	4d 89 c1             	mov    r9,r8
   140003e29:	41 89 c8             	mov    r8d,ecx
   140003e2c:	48 89 c2             	mov    rdx,rax
   140003e2f:	b9 02 00 00 00       	mov    ecx,0x2
   140003e34:	e8 88 fe ff ff       	call   140003cc1 <__pformat_cvt>
   140003e39:	48 83 c4 58          	add    rsp,0x58
   140003e3d:	5b                   	pop    rbx
   140003e3e:	5d                   	pop    rbp
   140003e3f:	c3                   	ret

0000000140003e40 <__pformat_fcvt>:
   140003e40:	55                   	push   rbp
   140003e41:	53                   	push   rbx
   140003e42:	48 83 ec 58          	sub    rsp,0x58
   140003e46:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003e4b:	48 89 cb             	mov    rbx,rcx
   140003e4e:	db 2b                	fld    TBYTE PTR [rbx]
   140003e50:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003e53:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003e56:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003e5a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003e5e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003e61:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003e64:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003e68:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003e6b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e6f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003e73:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003e78:	4d 89 c1             	mov    r9,r8
   140003e7b:	41 89 c8             	mov    r8d,ecx
   140003e7e:	48 89 c2             	mov    rdx,rax
   140003e81:	b9 03 00 00 00       	mov    ecx,0x3
   140003e86:	e8 36 fe ff ff       	call   140003cc1 <__pformat_cvt>
   140003e8b:	48 83 c4 58          	add    rsp,0x58
   140003e8f:	5b                   	pop    rbx
   140003e90:	5d                   	pop    rbp
   140003e91:	c3                   	ret

0000000140003e92 <__pformat_emit_radix_point>:
   140003e92:	55                   	push   rbp
   140003e93:	53                   	push   rbx
   140003e94:	48 83 ec 68          	sub    rsp,0x68
   140003e98:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003e9d:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003ea1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ea5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003ea8:	83 f8 fd             	cmp    eax,0xfffffffd
   140003eab:	75 48                	jne    140003ef5 <__pformat_emit_radix_point+0x63>
   140003ead:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003eb4:	00 
   140003eb5:	e8 56 57 00 00       	call   140009610 <localeconv>
   140003eba:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003ebd:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003ec1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003ec5:	49 89 c9             	mov    r9,rcx
   140003ec8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003ece:	48 89 c1             	mov    rcx,rax
   140003ed1:	e8 6a 51 00 00       	call   140009040 <mbrtowc>
   140003ed6:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003ed9:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003edd:	7e 0c                	jle    140003eeb <__pformat_emit_radix_point+0x59>
   140003edf:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003ee3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ee7:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003eeb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003eef:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140003ef2:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140003ef5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ef9:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003efd:	66 85 c0             	test   ax,ax
   140003f00:	0f 84 b8 00 00 00    	je     140003fbe <__pformat_emit_radix_point+0x12c>
   140003f06:	48 89 e0             	mov    rax,rsp
   140003f09:	48 89 c3             	mov    rbx,rax
   140003f0c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f10:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003f13:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f16:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f19:	48 63 d0             	movsxd rdx,eax
   140003f1c:	48 83 ea 01          	sub    rdx,0x1
   140003f20:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140003f24:	48 98                	cdqe
   140003f26:	48 83 c0 0f          	add    rax,0xf
   140003f2a:	48 c1 e8 04          	shr    rax,0x4
   140003f2e:	48 c1 e0 04          	shl    rax,0x4
   140003f32:	e8 59 f1 ff ff       	call   140003090 <___chkstk_ms>
   140003f37:	48 29 c4             	sub    rsp,rax
   140003f3a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003f3f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003f43:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   140003f4a:	00 
   140003f4b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003f4f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140003f53:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140003f57:	0f b7 d0             	movzx  edx,ax
   140003f5a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003f5e:	49 89 c8             	mov    r8,rcx
   140003f61:	48 89 c1             	mov    rcx,rax
   140003f64:	e8 87 50 00 00       	call   140008ff0 <wcrtomb>
   140003f69:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003f6c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003f70:	7e 36                	jle    140003fa8 <__pformat_emit_radix_point+0x116>
   140003f72:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003f76:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003f7a:	eb 1d                	jmp    140003f99 <__pformat_emit_radix_point+0x107>
   140003f7c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003f80:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003f84:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003f88:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003f8b:	0f be c0             	movsx  eax,al
   140003f8e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003f92:	89 c1                	mov    ecx,eax
   140003f94:	e8 b7 f1 ff ff       	call   140003150 <__pformat_putc>
   140003f99:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003f9c:	8d 50 ff             	lea    edx,[rax-0x1]
   140003f9f:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003fa2:	85 c0                	test   eax,eax
   140003fa4:	7f d6                	jg     140003f7c <__pformat_emit_radix_point+0xea>
   140003fa6:	eb 11                	jmp    140003fb9 <__pformat_emit_radix_point+0x127>
   140003fa8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fac:	48 89 c2             	mov    rdx,rax
   140003faf:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003fb4:	e8 97 f1 ff ff       	call   140003150 <__pformat_putc>
   140003fb9:	48 89 dc             	mov    rsp,rbx
   140003fbc:	eb 11                	jmp    140003fcf <__pformat_emit_radix_point+0x13d>
   140003fbe:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fc2:	48 89 c2             	mov    rdx,rax
   140003fc5:	b9 2e 00 00 00       	mov    ecx,0x2e
   140003fca:	e8 81 f1 ff ff       	call   140003150 <__pformat_putc>
   140003fcf:	90                   	nop
   140003fd0:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003fd4:	5b                   	pop    rbx
   140003fd5:	5d                   	pop    rbp
   140003fd6:	c3                   	ret

0000000140003fd7 <__pformat_emit_numeric_value>:
   140003fd7:	55                   	push   rbp
   140003fd8:	48 89 e5             	mov    rbp,rsp
   140003fdb:	48 83 ec 30          	sub    rsp,0x30
   140003fdf:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003fe2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140003fe6:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   140003fea:	75 0e                	jne    140003ffa <__pformat_emit_numeric_value+0x23>
   140003fec:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003ff0:	48 89 c1             	mov    rcx,rax
   140003ff3:	e8 9a fe ff ff       	call   140003e92 <__pformat_emit_radix_point>
   140003ff8:	eb 43                	jmp    14000403d <__pformat_emit_numeric_value+0x66>
   140003ffa:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   140003ffe:	75 2f                	jne    14000402f <__pformat_emit_numeric_value+0x58>
   140004000:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004004:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004008:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   14000400c:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004010:	66 85 c0             	test   ax,ax
   140004013:	74 28                	je     14000403d <__pformat_emit_numeric_value+0x66>
   140004015:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004019:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000401d:	49 89 d0             	mov    r8,rdx
   140004020:	ba 01 00 00 00       	mov    edx,0x1
   140004025:	48 89 c1             	mov    rcx,rax
   140004028:	e8 2c f3 ff ff       	call   140003359 <__pformat_wputchars>
   14000402d:	eb 0e                	jmp    14000403d <__pformat_emit_numeric_value+0x66>
   14000402f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004033:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004036:	89 c1                	mov    ecx,eax
   140004038:	e8 13 f1 ff ff       	call   140003150 <__pformat_putc>
   14000403d:	90                   	nop
   14000403e:	48 83 c4 30          	add    rsp,0x30
   140004042:	5d                   	pop    rbp
   140004043:	c3                   	ret

0000000140004044 <__pformat_emit_inf_or_nan>:
   140004044:	55                   	push   rbp
   140004045:	48 89 e5             	mov    rbp,rsp
   140004048:	48 83 ec 40          	sub    rsp,0x40
   14000404c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000404f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004053:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004057:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000405b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000405f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004063:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000406a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000406e:	74 11                	je     140004081 <__pformat_emit_inf_or_nan+0x3d>
   140004070:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004074:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004078:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000407c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000407f:	eb 3e                	jmp    1400040bf <__pformat_emit_inf_or_nan+0x7b>
   140004081:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004085:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004088:	25 00 01 00 00       	and    eax,0x100
   14000408d:	85 c0                	test   eax,eax
   14000408f:	74 11                	je     1400040a2 <__pformat_emit_inf_or_nan+0x5e>
   140004091:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004095:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004099:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000409d:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400040a0:	eb 1d                	jmp    1400040bf <__pformat_emit_inf_or_nan+0x7b>
   1400040a2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040a6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040a9:	83 e0 40             	and    eax,0x40
   1400040ac:	85 c0                	test   eax,eax
   1400040ae:	74 0f                	je     1400040bf <__pformat_emit_inf_or_nan+0x7b>
   1400040b0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040b4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040b8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040bc:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400040bf:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400040c6:	eb 38                	jmp    140004100 <__pformat_emit_inf_or_nan+0xbc>
   1400040c8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400040cc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040d0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040d4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400040d7:	83 e0 df             	and    eax,0xffffffdf
   1400040da:	41 89 c0             	mov    r8d,eax
   1400040dd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040e1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400040e4:	83 e0 20             	and    eax,0x20
   1400040e7:	89 c1                	mov    ecx,eax
   1400040e9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400040ed:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400040f1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400040f5:	44 89 c2             	mov    edx,r8d
   1400040f8:	09 ca                	or     edx,ecx
   1400040fa:	88 10                	mov    BYTE PTR [rax],dl
   1400040fc:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004100:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004104:	7f c2                	jg     1400040c8 <__pformat_emit_inf_or_nan+0x84>
   140004106:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000410a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000410e:	48 29 c2             	sub    rdx,rax
   140004111:	89 d1                	mov    ecx,edx
   140004113:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004117:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000411b:	49 89 d0             	mov    r8,rdx
   14000411e:	89 ca                	mov    edx,ecx
   140004120:	48 89 c1             	mov    rcx,rax
   140004123:	e8 ac f0 ff ff       	call   1400031d4 <__pformat_putchars>
   140004128:	90                   	nop
   140004129:	48 83 c4 40          	add    rsp,0x40
   14000412d:	5d                   	pop    rbp
   14000412e:	c3                   	ret

000000014000412f <__pformat_emit_float>:
   14000412f:	55                   	push   rbp
   140004130:	48 89 e5             	mov    rbp,rsp
   140004133:	48 83 ec 30          	sub    rsp,0x30
   140004137:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000413a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000413e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004142:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004146:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000414a:	7e 2e                	jle    14000417a <__pformat_emit_float+0x4b>
   14000414c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004150:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004153:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004156:	7f 15                	jg     14000416d <__pformat_emit_float+0x3e>
   140004158:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000415c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000415f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004162:	89 c2                	mov    edx,eax
   140004164:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004168:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000416b:	eb 29                	jmp    140004196 <__pformat_emit_float+0x67>
   14000416d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004171:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004178:	eb 1c                	jmp    140004196 <__pformat_emit_float+0x67>
   14000417a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000417e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004181:	85 c0                	test   eax,eax
   140004183:	7e 11                	jle    140004196 <__pformat_emit_float+0x67>
   140004185:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004189:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000418c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000418f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004193:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004196:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000419a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000419d:	85 c0                	test   eax,eax
   14000419f:	78 2b                	js     1400041cc <__pformat_emit_float+0x9d>
   1400041a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041a5:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400041a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041ac:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041af:	39 c2                	cmp    edx,eax
   1400041b1:	7e 19                	jle    1400041cc <__pformat_emit_float+0x9d>
   1400041b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041b7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400041ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041be:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041c1:	29 c2                	sub    edx,eax
   1400041c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041c7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400041ca:	eb 0b                	jmp    1400041d7 <__pformat_emit_float+0xa8>
   1400041cc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041d0:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400041d7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041db:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400041de:	85 c0                	test   eax,eax
   1400041e0:	7e 2c                	jle    14000420e <__pformat_emit_float+0xdf>
   1400041e2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041e6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400041e9:	85 c0                	test   eax,eax
   1400041eb:	7f 10                	jg     1400041fd <__pformat_emit_float+0xce>
   1400041ed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400041f1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041f4:	25 00 08 00 00       	and    eax,0x800
   1400041f9:	85 c0                	test   eax,eax
   1400041fb:	74 11                	je     14000420e <__pformat_emit_float+0xdf>
   1400041fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004201:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004204:	8d 50 ff             	lea    edx,[rax-0x1]
   140004207:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000420b:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000420e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004212:	7e 64                	jle    140004278 <__pformat_emit_float+0x149>
   140004214:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004218:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000421b:	25 00 10 00 00       	and    eax,0x1000
   140004220:	85 c0                	test   eax,eax
   140004222:	74 54                	je     140004278 <__pformat_emit_float+0x149>
   140004224:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004228:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000422c:	66 85 c0             	test   ax,ax
   14000422f:	74 47                	je     140004278 <__pformat_emit_float+0x149>
   140004231:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004234:	83 c0 02             	add    eax,0x2
   140004237:	48 63 d0             	movsxd rdx,eax
   14000423a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004241:	48 c1 ea 20          	shr    rdx,0x20
   140004245:	c1 f8 1f             	sar    eax,0x1f
   140004248:	29 c2                	sub    edx,eax
   14000424a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000424d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004250:	eb 15                	jmp    140004267 <__pformat_emit_float+0x138>
   140004252:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004256:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000425a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000425d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004260:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004264:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004267:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000426b:	7e 0b                	jle    140004278 <__pformat_emit_float+0x149>
   14000426d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004271:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004274:	85 c0                	test   eax,eax
   140004276:	7f da                	jg     140004252 <__pformat_emit_float+0x123>
   140004278:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000427c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000427f:	85 c0                	test   eax,eax
   140004281:	7e 27                	jle    1400042aa <__pformat_emit_float+0x17b>
   140004283:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004287:	75 10                	jne    140004299 <__pformat_emit_float+0x16a>
   140004289:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004290:	25 c0 01 00 00       	and    eax,0x1c0
   140004295:	85 c0                	test   eax,eax
   140004297:	74 11                	je     1400042aa <__pformat_emit_float+0x17b>
   140004299:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000429d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042a0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400042a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042aa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ae:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042b1:	85 c0                	test   eax,eax
   1400042b3:	7e 38                	jle    1400042ed <__pformat_emit_float+0x1be>
   1400042b5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400042bc:	25 00 06 00 00       	and    eax,0x600
   1400042c1:	85 c0                	test   eax,eax
   1400042c3:	75 28                	jne    1400042ed <__pformat_emit_float+0x1be>
   1400042c5:	eb 11                	jmp    1400042d8 <__pformat_emit_float+0x1a9>
   1400042c7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042cb:	48 89 c2             	mov    rdx,rax
   1400042ce:	b9 20 00 00 00       	mov    ecx,0x20
   1400042d3:	e8 78 ee ff ff       	call   140003150 <__pformat_putc>
   1400042d8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042dc:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042df:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400042e2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400042e6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400042e9:	85 c0                	test   eax,eax
   1400042eb:	7f da                	jg     1400042c7 <__pformat_emit_float+0x198>
   1400042ed:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   1400042f1:	74 13                	je     140004306 <__pformat_emit_float+0x1d7>
   1400042f3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042f7:	48 89 c2             	mov    rdx,rax
   1400042fa:	b9 2d 00 00 00       	mov    ecx,0x2d
   1400042ff:	e8 4c ee ff ff       	call   140003150 <__pformat_putc>
   140004304:	eb 42                	jmp    140004348 <__pformat_emit_float+0x219>
   140004306:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000430a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000430d:	25 00 01 00 00       	and    eax,0x100
   140004312:	85 c0                	test   eax,eax
   140004314:	74 13                	je     140004329 <__pformat_emit_float+0x1fa>
   140004316:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000431a:	48 89 c2             	mov    rdx,rax
   14000431d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004322:	e8 29 ee ff ff       	call   140003150 <__pformat_putc>
   140004327:	eb 1f                	jmp    140004348 <__pformat_emit_float+0x219>
   140004329:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000432d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004330:	83 e0 40             	and    eax,0x40
   140004333:	85 c0                	test   eax,eax
   140004335:	74 11                	je     140004348 <__pformat_emit_float+0x219>
   140004337:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000433b:	48 89 c2             	mov    rdx,rax
   14000433e:	b9 20 00 00 00       	mov    ecx,0x20
   140004343:	e8 08 ee ff ff       	call   140003150 <__pformat_putc>
   140004348:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000434c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000434f:	85 c0                	test   eax,eax
   140004351:	7e 3b                	jle    14000438e <__pformat_emit_float+0x25f>
   140004353:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004357:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000435a:	25 00 06 00 00       	and    eax,0x600
   14000435f:	3d 00 02 00 00       	cmp    eax,0x200
   140004364:	75 28                	jne    14000438e <__pformat_emit_float+0x25f>
   140004366:	eb 11                	jmp    140004379 <__pformat_emit_float+0x24a>
   140004368:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436c:	48 89 c2             	mov    rdx,rax
   14000436f:	b9 30 00 00 00       	mov    ecx,0x30
   140004374:	e8 d7 ed ff ff       	call   140003150 <__pformat_putc>
   140004379:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000437d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004380:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004383:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004387:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000438a:	85 c0                	test   eax,eax
   14000438c:	7f da                	jg     140004368 <__pformat_emit_float+0x239>
   14000438e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004392:	0f 8e a7 00 00 00    	jle    14000443f <__pformat_emit_float+0x310>
   140004398:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000439c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000439f:	84 c0                	test   al,al
   1400043a1:	74 14                	je     1400043b7 <__pformat_emit_float+0x288>
   1400043a3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400043a7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400043ab:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400043af:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400043b2:	0f be c0             	movsx  eax,al
   1400043b5:	eb 05                	jmp    1400043bc <__pformat_emit_float+0x28d>
   1400043b7:	b8 30 00 00 00       	mov    eax,0x30
   1400043bc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043c0:	89 c1                	mov    ecx,eax
   1400043c2:	e8 89 ed ff ff       	call   140003150 <__pformat_putc>
   1400043c7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400043cb:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400043cf:	74 62                	je     140004433 <__pformat_emit_float+0x304>
   1400043d1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043d5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043d8:	25 00 10 00 00       	and    eax,0x1000
   1400043dd:	85 c0                	test   eax,eax
   1400043df:	74 52                	je     140004433 <__pformat_emit_float+0x304>
   1400043e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043e5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400043e9:	66 85 c0             	test   ax,ax
   1400043ec:	74 45                	je     140004433 <__pformat_emit_float+0x304>
   1400043ee:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   1400043f1:	48 63 c1             	movsxd rax,ecx
   1400043f4:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   1400043fb:	48 c1 e8 20          	shr    rax,0x20
   1400043ff:	48 89 c2             	mov    rdx,rax
   140004402:	89 c8                	mov    eax,ecx
   140004404:	c1 f8 1f             	sar    eax,0x1f
   140004407:	29 c2                	sub    edx,eax
   140004409:	89 d0                	mov    eax,edx
   14000440b:	01 c0                	add    eax,eax
   14000440d:	01 d0                	add    eax,edx
   14000440f:	29 c1                	sub    ecx,eax
   140004411:	89 ca                	mov    edx,ecx
   140004413:	85 d2                	test   edx,edx
   140004415:	75 1c                	jne    140004433 <__pformat_emit_float+0x304>
   140004417:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000441b:	48 83 c0 20          	add    rax,0x20
   14000441f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004423:	49 89 d0             	mov    r8,rdx
   140004426:	ba 01 00 00 00       	mov    edx,0x1
   14000442b:	48 89 c1             	mov    rcx,rax
   14000442e:	e8 26 ef ff ff       	call   140003359 <__pformat_wputchars>
   140004433:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004437:	0f 8f 5b ff ff ff    	jg     140004398 <__pformat_emit_float+0x269>
   14000443d:	eb 11                	jmp    140004450 <__pformat_emit_float+0x321>
   14000443f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004443:	48 89 c2             	mov    rdx,rax
   140004446:	b9 30 00 00 00       	mov    ecx,0x30
   14000444b:	e8 00 ed ff ff       	call   140003150 <__pformat_putc>
   140004450:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004454:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004457:	85 c0                	test   eax,eax
   140004459:	7f 10                	jg     14000446b <__pformat_emit_float+0x33c>
   14000445b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000445f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004462:	25 00 08 00 00       	and    eax,0x800
   140004467:	85 c0                	test   eax,eax
   140004469:	74 0c                	je     140004477 <__pformat_emit_float+0x348>
   14000446b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000446f:	48 89 c1             	mov    rcx,rax
   140004472:	e8 1b fa ff ff       	call   140003e92 <__pformat_emit_radix_point>
   140004477:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000447b:	79 5f                	jns    1400044dc <__pformat_emit_float+0x3ad>
   14000447d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004481:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004484:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004487:	01 c2                	add    edx,eax
   140004489:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000448d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004490:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004494:	48 89 c2             	mov    rdx,rax
   140004497:	b9 30 00 00 00       	mov    ecx,0x30
   14000449c:	e8 af ec ff ff       	call   140003150 <__pformat_putc>
   1400044a1:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   1400044a5:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044a9:	78 e5                	js     140004490 <__pformat_emit_float+0x361>
   1400044ab:	eb 2f                	jmp    1400044dc <__pformat_emit_float+0x3ad>
   1400044ad:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044b1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044b4:	84 c0                	test   al,al
   1400044b6:	74 14                	je     1400044cc <__pformat_emit_float+0x39d>
   1400044b8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044bc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400044c0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400044c4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044c7:	0f be c0             	movsx  eax,al
   1400044ca:	eb 05                	jmp    1400044d1 <__pformat_emit_float+0x3a2>
   1400044cc:	b8 30 00 00 00       	mov    eax,0x30
   1400044d1:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044d5:	89 c1                	mov    ecx,eax
   1400044d7:	e8 74 ec ff ff       	call   140003150 <__pformat_putc>
   1400044dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044e0:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400044e3:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400044e6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044ea:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   1400044ed:	85 c0                	test   eax,eax
   1400044ef:	7f bc                	jg     1400044ad <__pformat_emit_float+0x37e>
   1400044f1:	90                   	nop
   1400044f2:	90                   	nop
   1400044f3:	48 83 c4 30          	add    rsp,0x30
   1400044f7:	5d                   	pop    rbp
   1400044f8:	c3                   	ret

00000001400044f9 <__pformat_emit_efloat>:
   1400044f9:	55                   	push   rbp
   1400044fa:	48 89 e5             	mov    rbp,rsp
   1400044fd:	48 83 ec 50          	sub    rsp,0x50
   140004501:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004504:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004508:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000450c:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004510:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004517:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000451b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000451f:	79 09                	jns    14000452a <__pformat_emit_efloat+0x31>
   140004521:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004528:	eb 05                	jmp    14000452f <__pformat_emit_efloat+0x36>
   14000452a:	b8 00 00 00 00       	mov    eax,0x0
   14000452f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004533:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004536:	48 98                	cdqe
   140004538:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000453c:	eb 04                	jmp    140004542 <__pformat_emit_efloat+0x49>
   14000453e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004542:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004545:	48 63 d0             	movsxd rdx,eax
   140004548:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000454f:	48 c1 ea 20          	shr    rdx,0x20
   140004553:	89 d1                	mov    ecx,edx
   140004555:	c1 f9 02             	sar    ecx,0x2
   140004558:	99                   	cdq
   140004559:	89 c8                	mov    eax,ecx
   14000455b:	29 d0                	sub    eax,edx
   14000455d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004560:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004564:	75 d8                	jne    14000453e <__pformat_emit_efloat+0x45>
   140004566:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000456a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000456d:	83 f8 ff             	cmp    eax,0xffffffff
   140004570:	75 0b                	jne    14000457d <__pformat_emit_efloat+0x84>
   140004572:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004576:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000457d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004581:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004584:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004587:	7d 0a                	jge    140004593 <__pformat_emit_efloat+0x9a>
   140004589:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000458d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004590:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004593:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004597:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000459a:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   14000459e:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400045a1:	7d 15                	jge    1400045b8 <__pformat_emit_efloat+0xbf>
   1400045a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045a7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400045aa:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   1400045ad:	89 c2                	mov    edx,eax
   1400045af:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045b3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400045b6:	eb 0b                	jmp    1400045c3 <__pformat_emit_efloat+0xca>
   1400045b8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045bc:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400045c3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400045c7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400045cb:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400045ce:	49 89 c9             	mov    r9,rcx
   1400045d1:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400045d7:	89 c1                	mov    ecx,eax
   1400045d9:	e8 51 fb ff ff       	call   14000412f <__pformat_emit_float>
   1400045de:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045e2:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   1400045e5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045e9:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400045ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045f0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400045f3:	0d c0 01 00 00       	or     eax,0x1c0
   1400045f8:	89 c2                	mov    edx,eax
   1400045fa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045fe:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004601:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004605:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004608:	83 e0 20             	and    eax,0x20
   14000460b:	83 c8 45             	or     eax,0x45
   14000460e:	89 c1                	mov    ecx,eax
   140004610:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004614:	48 89 c2             	mov    rdx,rax
   140004617:	e8 34 eb ff ff       	call   140003150 <__pformat_putc>
   14000461c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004620:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004623:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004626:	83 ea 01             	sub    edx,0x1
   140004629:	01 c2                	add    edx,eax
   14000462b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000462f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004632:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004636:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000463a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000463e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004642:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004646:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000464a:	48 89 c1             	mov    rcx,rax
   14000464d:	e8 69 ef ff ff       	call   1400035bb <__pformat_int>
   140004652:	90                   	nop
   140004653:	48 83 c4 50          	add    rsp,0x50
   140004657:	5d                   	pop    rbp
   140004658:	c3                   	ret

0000000140004659 <__pformat_float>:
   140004659:	55                   	push   rbp
   14000465a:	53                   	push   rbx
   14000465b:	48 83 ec 58          	sub    rsp,0x58
   14000465f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004664:	48 89 cb             	mov    rbx,rcx
   140004667:	db 2b                	fld    TBYTE PTR [rbx]
   140004669:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000466c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004670:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004674:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004677:	85 c0                	test   eax,eax
   140004679:	79 0b                	jns    140004686 <__pformat_float+0x2d>
   14000467b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000467f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004686:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000468a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000468d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004690:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004693:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   140004697:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000469b:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000469f:	4d 89 c1             	mov    r9,r8
   1400046a2:	49 89 c8             	mov    r8,rcx
   1400046a5:	48 89 c1             	mov    rcx,rax
   1400046a8:	e8 93 f7 ff ff       	call   140003e40 <__pformat_fcvt>
   1400046ad:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400046b1:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400046b4:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400046b9:	75 17                	jne    1400046d2 <__pformat_float+0x79>
   1400046bb:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400046be:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046c2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400046c6:	49 89 c8             	mov    r8,rcx
   1400046c9:	89 c1                	mov    ecx,eax
   1400046cb:	e8 74 f9 ff ff       	call   140004044 <__pformat_emit_inf_or_nan>
   1400046d0:	eb 43                	jmp    140004715 <__pformat_float+0xbc>
   1400046d2:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400046d5:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400046d8:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400046dc:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400046e0:	4d 89 c1             	mov    r9,r8
   1400046e3:	41 89 c8             	mov    r8d,ecx
   1400046e6:	89 c1                	mov    ecx,eax
   1400046e8:	e8 42 fa ff ff       	call   14000412f <__pformat_emit_float>
   1400046ed:	eb 11                	jmp    140004700 <__pformat_float+0xa7>
   1400046ef:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046f3:	48 89 c2             	mov    rdx,rax
   1400046f6:	b9 20 00 00 00       	mov    ecx,0x20
   1400046fb:	e8 50 ea ff ff       	call   140003150 <__pformat_putc>
   140004700:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004704:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004707:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000470a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000470e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004711:	85 c0                	test   eax,eax
   140004713:	7f da                	jg     1400046ef <__pformat_float+0x96>
   140004715:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004719:	48 89 c1             	mov    rcx,rax
   14000471c:	e8 4e 17 00 00       	call   140005e6f <__freedtoa>
   140004721:	90                   	nop
   140004722:	48 83 c4 58          	add    rsp,0x58
   140004726:	5b                   	pop    rbx
   140004727:	5d                   	pop    rbp
   140004728:	c3                   	ret

0000000140004729 <__pformat_efloat>:
   140004729:	55                   	push   rbp
   14000472a:	53                   	push   rbx
   14000472b:	48 83 ec 58          	sub    rsp,0x58
   14000472f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004734:	48 89 cb             	mov    rbx,rcx
   140004737:	db 2b                	fld    TBYTE PTR [rbx]
   140004739:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000473c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004740:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004744:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004747:	85 c0                	test   eax,eax
   140004749:	79 0b                	jns    140004756 <__pformat_efloat+0x2d>
   14000474b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000474f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004756:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000475a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000475d:	8d 50 01             	lea    edx,[rax+0x1]
   140004760:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004763:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004766:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000476a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000476e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004772:	4d 89 c1             	mov    r9,r8
   140004775:	49 89 c8             	mov    r8,rcx
   140004778:	48 89 c1             	mov    rcx,rax
   14000477b:	e8 6e f6 ff ff       	call   140003dee <__pformat_ecvt>
   140004780:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004784:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004787:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000478c:	75 17                	jne    1400047a5 <__pformat_efloat+0x7c>
   14000478e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004791:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004795:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004799:	49 89 c8             	mov    r8,rcx
   14000479c:	89 c1                	mov    ecx,eax
   14000479e:	e8 a1 f8 ff ff       	call   140004044 <__pformat_emit_inf_or_nan>
   1400047a3:	eb 1b                	jmp    1400047c0 <__pformat_efloat+0x97>
   1400047a5:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400047a8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047ab:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400047af:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047b3:	4d 89 c1             	mov    r9,r8
   1400047b6:	41 89 c8             	mov    r8d,ecx
   1400047b9:	89 c1                	mov    ecx,eax
   1400047bb:	e8 39 fd ff ff       	call   1400044f9 <__pformat_emit_efloat>
   1400047c0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400047c4:	48 89 c1             	mov    rcx,rax
   1400047c7:	e8 a3 16 00 00       	call   140005e6f <__freedtoa>
   1400047cc:	90                   	nop
   1400047cd:	48 83 c4 58          	add    rsp,0x58
   1400047d1:	5b                   	pop    rbx
   1400047d2:	5d                   	pop    rbp
   1400047d3:	c3                   	ret

00000001400047d4 <__pformat_gfloat>:
   1400047d4:	55                   	push   rbp
   1400047d5:	53                   	push   rbx
   1400047d6:	48 83 ec 58          	sub    rsp,0x58
   1400047da:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400047df:	48 89 cb             	mov    rbx,rcx
   1400047e2:	db 2b                	fld    TBYTE PTR [rbx]
   1400047e4:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400047e7:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400047eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047ef:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400047f2:	85 c0                	test   eax,eax
   1400047f4:	79 0d                	jns    140004803 <__pformat_gfloat+0x2f>
   1400047f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400047fa:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004801:	eb 16                	jmp    140004819 <__pformat_gfloat+0x45>
   140004803:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004807:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000480a:	85 c0                	test   eax,eax
   14000480c:	75 0b                	jne    140004819 <__pformat_gfloat+0x45>
   14000480e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004812:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004819:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000481d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004820:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004823:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004826:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000482a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000482e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004832:	4d 89 c1             	mov    r9,r8
   140004835:	49 89 c8             	mov    r8,rcx
   140004838:	48 89 c1             	mov    rcx,rax
   14000483b:	e8 ae f5 ff ff       	call   140003dee <__pformat_ecvt>
   140004840:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004844:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004847:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000484c:	75 1a                	jne    140004868 <__pformat_gfloat+0x94>
   14000484e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004851:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004855:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004859:	49 89 c8             	mov    r8,rcx
   14000485c:	89 c1                	mov    ecx,eax
   14000485e:	e8 e1 f7 ff ff       	call   140004044 <__pformat_emit_inf_or_nan>
   140004863:	e9 14 01 00 00       	jmp    14000497c <__pformat_gfloat+0x1a8>
   140004868:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000486b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000486e:	0f 8c b2 00 00 00    	jl     140004926 <__pformat_gfloat+0x152>
   140004874:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004878:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000487b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000487e:	39 c2                	cmp    edx,eax
   140004880:	0f 8c a0 00 00 00    	jl     140004926 <__pformat_gfloat+0x152>
   140004886:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000488a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000488d:	25 00 08 00 00       	and    eax,0x800
   140004892:	85 c0                	test   eax,eax
   140004894:	74 15                	je     1400048ab <__pformat_gfloat+0xd7>
   140004896:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000489a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000489d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048a0:	29 c2                	sub    edx,eax
   1400048a2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048a6:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400048a9:	eb 20                	jmp    1400048cb <__pformat_gfloat+0xf7>
   1400048ab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400048af:	48 89 c1             	mov    rcx,rax
   1400048b2:	e8 89 4d 00 00       	call   140009640 <strlen>
   1400048b7:	89 c1                	mov    ecx,eax
   1400048b9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400048bc:	89 c2                	mov    edx,eax
   1400048be:	89 c8                	mov    eax,ecx
   1400048c0:	29 d0                	sub    eax,edx
   1400048c2:	89 c2                	mov    edx,eax
   1400048c4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048c8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400048cb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048cf:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400048d2:	85 c0                	test   eax,eax
   1400048d4:	79 0b                	jns    1400048e1 <__pformat_gfloat+0x10d>
   1400048d6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048da:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   1400048e1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400048e4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048e7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400048eb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048ef:	4d 89 c1             	mov    r9,r8
   1400048f2:	41 89 c8             	mov    r8d,ecx
   1400048f5:	89 c1                	mov    ecx,eax
   1400048f7:	e8 33 f8 ff ff       	call   14000412f <__pformat_emit_float>
   1400048fc:	eb 11                	jmp    14000490f <__pformat_gfloat+0x13b>
   1400048fe:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004902:	48 89 c2             	mov    rdx,rax
   140004905:	b9 20 00 00 00       	mov    ecx,0x20
   14000490a:	e8 41 e8 ff ff       	call   140003150 <__pformat_putc>
   14000490f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004913:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004916:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004919:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000491d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004920:	85 c0                	test   eax,eax
   140004922:	7f da                	jg     1400048fe <__pformat_gfloat+0x12a>
   140004924:	eb 56                	jmp    14000497c <__pformat_gfloat+0x1a8>
   140004926:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000492a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000492d:	25 00 08 00 00       	and    eax,0x800
   140004932:	85 c0                	test   eax,eax
   140004934:	74 13                	je     140004949 <__pformat_gfloat+0x175>
   140004936:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000493a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000493d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004940:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004944:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004947:	eb 18                	jmp    140004961 <__pformat_gfloat+0x18d>
   140004949:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000494d:	48 89 c1             	mov    rcx,rax
   140004950:	e8 eb 4c 00 00       	call   140009640 <strlen>
   140004955:	83 e8 01             	sub    eax,0x1
   140004958:	89 c2                	mov    edx,eax
   14000495a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000495e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004961:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004964:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004967:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   14000496b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000496f:	4d 89 c1             	mov    r9,r8
   140004972:	41 89 c8             	mov    r8d,ecx
   140004975:	89 c1                	mov    ecx,eax
   140004977:	e8 7d fb ff ff       	call   1400044f9 <__pformat_emit_efloat>
   14000497c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004980:	48 89 c1             	mov    rcx,rax
   140004983:	e8 e7 14 00 00       	call   140005e6f <__freedtoa>
   140004988:	90                   	nop
   140004989:	48 83 c4 58          	add    rsp,0x58
   14000498d:	5b                   	pop    rbx
   14000498e:	5d                   	pop    rbp
   14000498f:	c3                   	ret

0000000140004990 <__pformat_emit_xfloat>:
   140004990:	55                   	push   rbp
   140004991:	53                   	push   rbx
   140004992:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004999:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   1400049a0:	00 
   1400049a1:	48 89 cb             	mov    rbx,rcx
   1400049a4:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400049a8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400049ac:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400049b0:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   1400049b6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400049b9:	48 85 c0             	test   rax,rax
   1400049bc:	75 09                	jne    1400049c7 <__pformat_emit_xfloat+0x37>
   1400049be:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049c2:	66 85 c0             	test   ax,ax
   1400049c5:	74 0b                	je     1400049d2 <__pformat_emit_xfloat+0x42>
   1400049c7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   1400049cb:	83 e8 03             	sub    eax,0x3
   1400049ce:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   1400049d2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049d6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049d9:	85 c0                	test   eax,eax
   1400049db:	0f 88 90 00 00 00    	js     140004a71 <__pformat_emit_xfloat+0xe1>
   1400049e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049e5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049e8:	83 f8 0e             	cmp    eax,0xe
   1400049eb:	0f 8f 80 00 00 00    	jg     140004a71 <__pformat_emit_xfloat+0xe1>
   1400049f1:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   1400049f4:	48 d1 e8             	shr    rax,1
   1400049f7:	48 89 03             	mov    QWORD PTR [rbx],rax
   1400049fa:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   1400049fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a01:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a04:	b9 0e 00 00 00       	mov    ecx,0xe
   140004a09:	29 c1                	sub    ecx,eax
   140004a0b:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a12:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004a18:	89 c1                	mov    ecx,eax
   140004a1a:	49 d3 e0             	shl    r8,cl
   140004a1d:	4c 89 c0             	mov    rax,r8
   140004a20:	48 01 d0             	add    rax,rdx
   140004a23:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a26:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a29:	48 85 c0             	test   rax,rax
   140004a2c:	78 0b                	js     140004a39 <__pformat_emit_xfloat+0xa9>
   140004a2e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a31:	48 01 c0             	add    rax,rax
   140004a34:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a37:	eb 15                	jmp    140004a4e <__pformat_emit_xfloat+0xbe>
   140004a39:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004a3d:	83 c0 04             	add    eax,0x4
   140004a40:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004a44:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a47:	48 c1 e8 03          	shr    rax,0x3
   140004a4b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a4e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004a51:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a55:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a58:	b9 0f 00 00 00       	mov    ecx,0xf
   140004a5d:	29 c1                	sub    ecx,eax
   140004a5f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004a66:	89 c1                	mov    ecx,eax
   140004a68:	48 d3 ea             	shr    rdx,cl
   140004a6b:	48 89 d0             	mov    rax,rdx
   140004a6e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004a71:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004a74:	48 85 c0             	test   rax,rax
   140004a77:	75 0f                	jne    140004a88 <__pformat_emit_xfloat+0xf8>
   140004a79:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a7d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a80:	85 c0                	test   eax,eax
   140004a82:	0f 8e f8 00 00 00    	jle    140004b80 <__pformat_emit_xfloat+0x1f0>
   140004a88:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a8c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a8f:	83 f8 0e             	cmp    eax,0xe
   140004a92:	7f 1a                	jg     140004aae <__pformat_emit_xfloat+0x11e>
   140004a94:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a98:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a9b:	85 c0                	test   eax,eax
   140004a9d:	78 0f                	js     140004aae <__pformat_emit_xfloat+0x11e>
   140004a9f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004aa3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004aa6:	83 c0 01             	add    eax,0x1
   140004aa9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004aac:	eb 07                	jmp    140004ab5 <__pformat_emit_xfloat+0x125>
   140004aae:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004ab5:	e9 bc 00 00 00       	jmp    140004b76 <__pformat_emit_xfloat+0x1e6>
   140004aba:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004abd:	83 e0 0f             	and    eax,0xf
   140004ac0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004ac3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004ac7:	75 36                	jne    140004aff <__pformat_emit_xfloat+0x16f>
   140004ac9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004acd:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004ad1:	72 1b                	jb     140004aee <__pformat_emit_xfloat+0x15e>
   140004ad3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ad7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ada:	25 00 08 00 00       	and    eax,0x800
   140004adf:	85 c0                	test   eax,eax
   140004ae1:	75 0b                	jne    140004aee <__pformat_emit_xfloat+0x15e>
   140004ae3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ae7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004aea:	85 c0                	test   eax,eax
   140004aec:	7e 2d                	jle    140004b1b <__pformat_emit_xfloat+0x18b>
   140004aee:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004af2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004af6:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004afa:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004afd:	eb 1c                	jmp    140004b1b <__pformat_emit_xfloat+0x18b>
   140004aff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b03:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b06:	85 c0                	test   eax,eax
   140004b08:	7e 11                	jle    140004b1b <__pformat_emit_xfloat+0x18b>
   140004b0a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b0e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b11:	8d 50 ff             	lea    edx,[rax-0x1]
   140004b14:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b18:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004b1b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004b1f:	75 15                	jne    140004b36 <__pformat_emit_xfloat+0x1a6>
   140004b21:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b25:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004b29:	72 0b                	jb     140004b36 <__pformat_emit_xfloat+0x1a6>
   140004b2b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b2f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b32:	85 c0                	test   eax,eax
   140004b34:	78 32                	js     140004b68 <__pformat_emit_xfloat+0x1d8>
   140004b36:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004b3a:	76 16                	jbe    140004b52 <__pformat_emit_xfloat+0x1c2>
   140004b3c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b3f:	8d 50 37             	lea    edx,[rax+0x37]
   140004b42:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b46:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b49:	83 e0 20             	and    eax,0x20
   140004b4c:	09 d0                	or     eax,edx
   140004b4e:	89 c1                	mov    ecx,eax
   140004b50:	eb 08                	jmp    140004b5a <__pformat_emit_xfloat+0x1ca>
   140004b52:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004b55:	83 c0 30             	add    eax,0x30
   140004b58:	89 c1                	mov    ecx,eax
   140004b5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004b5e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004b62:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004b66:	88 08                	mov    BYTE PTR [rax],cl
   140004b68:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b6b:	48 c1 e8 04          	shr    rax,0x4
   140004b6f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b72:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004b76:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004b7a:	0f 8f 3a ff ff ff    	jg     140004aba <__pformat_emit_xfloat+0x12a>
   140004b80:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004b84:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004b88:	75 39                	jne    140004bc3 <__pformat_emit_xfloat+0x233>
   140004b8a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b8e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b91:	85 c0                	test   eax,eax
   140004b93:	7f 10                	jg     140004ba5 <__pformat_emit_xfloat+0x215>
   140004b95:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b99:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004b9c:	25 00 08 00 00       	and    eax,0x800
   140004ba1:	85 c0                	test   eax,eax
   140004ba3:	74 0f                	je     140004bb4 <__pformat_emit_xfloat+0x224>
   140004ba5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004ba9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bad:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bb1:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004bb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004bb8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004bbc:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004bc0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004bc3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bc7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004bca:	85 c0                	test   eax,eax
   140004bcc:	0f 8e e3 00 00 00    	jle    140004cb5 <__pformat_emit_xfloat+0x325>
   140004bd2:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bd6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004bda:	48 29 c2             	sub    rdx,rax
   140004bdd:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004be0:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004be4:	98                   	cwde
   140004be5:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004be8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bec:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bef:	85 c0                	test   eax,eax
   140004bf1:	7e 0a                	jle    140004bfd <__pformat_emit_xfloat+0x26d>
   140004bf3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bfa:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004bfd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c01:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c04:	25 c0 01 00 00       	and    eax,0x1c0
   140004c09:	85 c0                	test   eax,eax
   140004c0b:	74 07                	je     140004c14 <__pformat_emit_xfloat+0x284>
   140004c0d:	b8 06 00 00 00       	mov    eax,0x6
   140004c12:	eb 05                	jmp    140004c19 <__pformat_emit_xfloat+0x289>
   140004c14:	b8 05 00 00 00       	mov    eax,0x5
   140004c19:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004c1c:	eb 0f                	jmp    140004c2d <__pformat_emit_xfloat+0x29d>
   140004c1e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004c22:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004c26:	83 c0 01             	add    eax,0x1
   140004c29:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004c2d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004c30:	48 63 d0             	movsxd rdx,eax
   140004c33:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004c3a:	48 c1 ea 20          	shr    rdx,0x20
   140004c3e:	89 d1                	mov    ecx,edx
   140004c40:	c1 f9 02             	sar    ecx,0x2
   140004c43:	99                   	cdq
   140004c44:	89 c8                	mov    eax,ecx
   140004c46:	29 d0                	sub    eax,edx
   140004c48:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004c4b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004c4f:	75 cd                	jne    140004c1e <__pformat_emit_xfloat+0x28e>
   140004c51:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c55:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c58:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004c5b:	7d 4d                	jge    140004caa <__pformat_emit_xfloat+0x31a>
   140004c5d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c61:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c64:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004c67:	89 c2                	mov    edx,eax
   140004c69:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c6d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004c70:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c74:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c77:	25 00 06 00 00       	and    eax,0x600
   140004c7c:	85 c0                	test   eax,eax
   140004c7e:	75 35                	jne    140004cb5 <__pformat_emit_xfloat+0x325>
   140004c80:	eb 11                	jmp    140004c93 <__pformat_emit_xfloat+0x303>
   140004c82:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c86:	48 89 c2             	mov    rdx,rax
   140004c89:	b9 20 00 00 00       	mov    ecx,0x20
   140004c8e:	e8 bd e4 ff ff       	call   140003150 <__pformat_putc>
   140004c93:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c97:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004c9a:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004c9d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ca1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004ca4:	85 c0                	test   eax,eax
   140004ca6:	7f da                	jg     140004c82 <__pformat_emit_xfloat+0x2f2>
   140004ca8:	eb 0b                	jmp    140004cb5 <__pformat_emit_xfloat+0x325>
   140004caa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cae:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004cb5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cb9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cbc:	25 80 00 00 00       	and    eax,0x80
   140004cc1:	85 c0                	test   eax,eax
   140004cc3:	74 13                	je     140004cd8 <__pformat_emit_xfloat+0x348>
   140004cc5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cc9:	48 89 c2             	mov    rdx,rax
   140004ccc:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004cd1:	e8 7a e4 ff ff       	call   140003150 <__pformat_putc>
   140004cd6:	eb 42                	jmp    140004d1a <__pformat_emit_xfloat+0x38a>
   140004cd8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cdc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cdf:	25 00 01 00 00       	and    eax,0x100
   140004ce4:	85 c0                	test   eax,eax
   140004ce6:	74 13                	je     140004cfb <__pformat_emit_xfloat+0x36b>
   140004ce8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cec:	48 89 c2             	mov    rdx,rax
   140004cef:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004cf4:	e8 57 e4 ff ff       	call   140003150 <__pformat_putc>
   140004cf9:	eb 1f                	jmp    140004d1a <__pformat_emit_xfloat+0x38a>
   140004cfb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cff:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d02:	83 e0 40             	and    eax,0x40
   140004d05:	85 c0                	test   eax,eax
   140004d07:	74 11                	je     140004d1a <__pformat_emit_xfloat+0x38a>
   140004d09:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d0d:	48 89 c2             	mov    rdx,rax
   140004d10:	b9 20 00 00 00       	mov    ecx,0x20
   140004d15:	e8 36 e4 ff ff       	call   140003150 <__pformat_putc>
   140004d1a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d1e:	48 89 c2             	mov    rdx,rax
   140004d21:	b9 30 00 00 00       	mov    ecx,0x30
   140004d26:	e8 25 e4 ff ff       	call   140003150 <__pformat_putc>
   140004d2b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d2f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d32:	83 e0 20             	and    eax,0x20
   140004d35:	83 c8 58             	or     eax,0x58
   140004d38:	89 c1                	mov    ecx,eax
   140004d3a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d3e:	48 89 c2             	mov    rdx,rax
   140004d41:	e8 0a e4 ff ff       	call   140003150 <__pformat_putc>
   140004d46:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d4a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d4d:	85 c0                	test   eax,eax
   140004d4f:	7e 54                	jle    140004da5 <__pformat_emit_xfloat+0x415>
   140004d51:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d55:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d58:	25 00 02 00 00       	and    eax,0x200
   140004d5d:	85 c0                	test   eax,eax
   140004d5f:	74 44                	je     140004da5 <__pformat_emit_xfloat+0x415>
   140004d61:	eb 11                	jmp    140004d74 <__pformat_emit_xfloat+0x3e4>
   140004d63:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d67:	48 89 c2             	mov    rdx,rax
   140004d6a:	b9 30 00 00 00       	mov    ecx,0x30
   140004d6f:	e8 dc e3 ff ff       	call   140003150 <__pformat_putc>
   140004d74:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d78:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d7b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004d7e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d82:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004d85:	85 c0                	test   eax,eax
   140004d87:	7f da                	jg     140004d63 <__pformat_emit_xfloat+0x3d3>
   140004d89:	eb 1a                	jmp    140004da5 <__pformat_emit_xfloat+0x415>
   140004d8b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004d90:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004d94:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004d97:	0f be c0             	movsx  eax,al
   140004d9a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004d9e:	89 c1                	mov    ecx,eax
   140004da0:	e8 32 f2 ff ff       	call   140003fd7 <__pformat_emit_numeric_value>
   140004da5:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004da9:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004dad:	72 dc                	jb     140004d8b <__pformat_emit_xfloat+0x3fb>
   140004daf:	eb 11                	jmp    140004dc2 <__pformat_emit_xfloat+0x432>
   140004db1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004db5:	48 89 c2             	mov    rdx,rax
   140004db8:	b9 30 00 00 00       	mov    ecx,0x30
   140004dbd:	e8 8e e3 ff ff       	call   140003150 <__pformat_putc>
   140004dc2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dc6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004dc9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dcc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004dd0:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004dd3:	85 c0                	test   eax,eax
   140004dd5:	7f da                	jg     140004db1 <__pformat_emit_xfloat+0x421>
   140004dd7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ddb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dde:	83 e0 20             	and    eax,0x20
   140004de1:	83 c8 50             	or     eax,0x50
   140004de4:	89 c1                	mov    ecx,eax
   140004de6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dea:	48 89 c2             	mov    rdx,rax
   140004ded:	e8 5e e3 ff ff       	call   140003150 <__pformat_putc>
   140004df2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004df6:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004df9:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004dfd:	01 c2                	add    edx,eax
   140004dff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e03:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004e06:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e0a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e0d:	0d c0 01 00 00       	or     eax,0x1c0
   140004e12:	89 c2                	mov    edx,eax
   140004e14:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e18:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004e1b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e1f:	66 85 c0             	test   ax,ax
   140004e22:	79 09                	jns    140004e2d <__pformat_emit_xfloat+0x49d>
   140004e24:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004e2b:	eb 05                	jmp    140004e32 <__pformat_emit_xfloat+0x4a2>
   140004e2d:	b8 00 00 00 00       	mov    eax,0x0
   140004e32:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004e36:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004e3a:	48 0f bf c0          	movsx  rax,ax
   140004e3e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004e42:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004e46:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004e4a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004e4e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004e52:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e56:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004e5a:	48 89 c1             	mov    rcx,rax
   140004e5d:	e8 59 e7 ff ff       	call   1400035bb <__pformat_int>
   140004e62:	90                   	nop
   140004e63:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004e6a:	5b                   	pop    rbx
   140004e6b:	5d                   	pop    rbp
   140004e6c:	c3                   	ret

0000000140004e6d <__pformat_xldouble>:
   140004e6d:	55                   	push   rbp
   140004e6e:	53                   	push   rbx
   140004e6f:	48 83 ec 78          	sub    rsp,0x78
   140004e73:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004e78:	48 89 cb             	mov    rbx,rcx
   140004e7b:	db 2b                	fld    TBYTE PTR [rbx]
   140004e7d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004e80:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004e84:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004e8b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004e8f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004e92:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004e95:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004e99:	48 89 c1             	mov    rcx,rax
   140004e9c:	e8 e5 ed ff ff       	call   140003c86 <init_fpreg_ldouble>
   140004ea1:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004ea4:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004ea7:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004eab:	48 89 c1             	mov    rcx,rax
   140004eae:	e8 ed 3d 00 00       	call   140008ca0 <__isnanl>
   140004eb3:	85 c0                	test   eax,eax
   140004eb5:	74 1d                	je     140004ed4 <__pformat_xldouble+0x67>
   140004eb7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004eba:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004ebe:	48 8d 15 81 64 00 00 	lea    rdx,[rip+0x6481]        # 14000b346 <.rdata+0x16>
   140004ec5:	49 89 c8             	mov    r8,rcx
   140004ec8:	89 c1                	mov    ecx,eax
   140004eca:	e8 75 f1 ff ff       	call   140004044 <__pformat_emit_inf_or_nan>
   140004ecf:	e9 aa 00 00 00       	jmp    140004f7e <__pformat_xldouble+0x111>
   140004ed4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004ed8:	98                   	cwde
   140004ed9:	25 00 80 00 00       	and    eax,0x8000
   140004ede:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004ee1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004ee5:	74 12                	je     140004ef9 <__pformat_xldouble+0x8c>
   140004ee7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eeb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004eee:	0c 80                	or     al,0x80
   140004ef0:	89 c2                	mov    edx,eax
   140004ef2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ef6:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004ef9:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004efc:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004eff:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004f03:	48 89 c1             	mov    rcx,rax
   140004f06:	e8 a5 3c 00 00       	call   140008bb0 <__fpclassifyl>
   140004f0b:	3d 00 05 00 00       	cmp    eax,0x500
   140004f10:	75 1a                	jne    140004f2c <__pformat_xldouble+0xbf>
   140004f12:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004f15:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004f19:	48 8d 15 2a 64 00 00 	lea    rdx,[rip+0x642a]        # 14000b34a <.rdata+0x1a>
   140004f20:	49 89 c8             	mov    r8,rcx
   140004f23:	89 c1                	mov    ecx,eax
   140004f25:	e8 1a f1 ff ff       	call   140004044 <__pformat_emit_inf_or_nan>
   140004f2a:	eb 52                	jmp    140004f7e <__pformat_xldouble+0x111>
   140004f2c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f30:	66 25 ff 7f          	and    ax,0x7fff
   140004f34:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f38:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f3c:	66 85 c0             	test   ax,ax
   140004f3f:	75 11                	jne    140004f52 <__pformat_xldouble+0xe5>
   140004f41:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f45:	48 85 c0             	test   rax,rax
   140004f48:	74 14                	je     140004f5e <__pformat_xldouble+0xf1>
   140004f4a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140004f50:	eb 0c                	jmp    140004f5e <__pformat_xldouble+0xf1>
   140004f52:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004f56:	66 2d ff 3f          	sub    ax,0x3fff
   140004f5a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140004f5e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004f62:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140004f66:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f6a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   140004f6e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f72:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140004f76:	48 89 c1             	mov    rcx,rax
   140004f79:	e8 12 fa ff ff       	call   140004990 <__pformat_emit_xfloat>
   140004f7e:	90                   	nop
   140004f7f:	48 83 c4 78          	add    rsp,0x78
   140004f83:	5b                   	pop    rbx
   140004f84:	5d                   	pop    rbp
   140004f85:	c3                   	ret

0000000140004f86 <__pformat_xdouble>:
   140004f86:	55                   	push   rbp
   140004f87:	48 89 e5             	mov    rbp,rsp
   140004f8a:	48 83 ec 60          	sub    rsp,0x60
   140004f8e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140004f93:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004f97:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f9e:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   140004fa1:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004fa5:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004fa8:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   140004fac:	48 89 c1             	mov    rcx,rax
   140004faf:	e8 d2 ec ff ff       	call   140003c86 <init_fpreg_ldouble>
   140004fb4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140004fb8:	66 48 0f 6e c0       	movq   xmm0,rax
   140004fbd:	e8 7e 3c 00 00       	call   140008c40 <__isnan>
   140004fc2:	85 c0                	test   eax,eax
   140004fc4:	74 1d                	je     140004fe3 <__pformat_xdouble+0x5d>
   140004fc6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fc9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140004fcd:	48 8d 15 72 63 00 00 	lea    rdx,[rip+0x6372]        # 14000b346 <.rdata+0x16>
   140004fd4:	49 89 c8             	mov    r8,rcx
   140004fd7:	89 c1                	mov    ecx,eax
   140004fd9:	e8 66 f0 ff ff       	call   140004044 <__pformat_emit_inf_or_nan>
   140004fde:	e9 f9 00 00 00       	jmp    1400050dc <__pformat_xdouble+0x156>
   140004fe3:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fe7:	98                   	cwde
   140004fe8:	25 00 80 00 00       	and    eax,0x8000
   140004fed:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004ff0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004ff4:	74 12                	je     140005008 <__pformat_xdouble+0x82>
   140004ff6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004ffa:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ffd:	0c 80                	or     al,0x80
   140004fff:	89 c2                	mov    edx,eax
   140005001:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005005:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005008:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000500c:	66 48 0f 6e c0       	movq   xmm0,rax
   140005011:	e8 1a 3b 00 00       	call   140008b30 <__fpclassify>
   140005016:	3d 00 05 00 00       	cmp    eax,0x500
   14000501b:	75 1d                	jne    14000503a <__pformat_xdouble+0xb4>
   14000501d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005020:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005024:	48 8d 15 1f 63 00 00 	lea    rdx,[rip+0x631f]        # 14000b34a <.rdata+0x1a>
   14000502b:	49 89 c8             	mov    r8,rcx
   14000502e:	89 c1                	mov    ecx,eax
   140005030:	e8 0f f0 ff ff       	call   140004044 <__pformat_emit_inf_or_nan>
   140005035:	e9 a2 00 00 00       	jmp    1400050dc <__pformat_xdouble+0x156>
   14000503a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000503e:	66 25 ff 7f          	and    ax,0x7fff
   140005042:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005046:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000504a:	66 85 c0             	test   ax,ax
   14000504d:	74 3b                	je     14000508a <__pformat_xdouble+0x104>
   14000504f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005053:	66 3d 00 3c          	cmp    ax,0x3c00
   140005057:	7f 31                	jg     14000508a <__pformat_xdouble+0x104>
   140005059:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000505d:	98                   	cwde
   14000505e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005063:	29 c2                	sub    edx,eax
   140005065:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005068:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000506c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000506f:	89 c1                	mov    ecx,eax
   140005071:	48 d3 ea             	shr    rdx,cl
   140005074:	48 89 d0             	mov    rax,rdx
   140005077:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000507b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000507f:	89 c2                	mov    edx,eax
   140005081:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005084:	01 d0                	add    eax,edx
   140005086:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000508a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000508e:	66 85 c0             	test   ax,ax
   140005091:	75 11                	jne    1400050a4 <__pformat_xdouble+0x11e>
   140005093:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005097:	48 85 c0             	test   rax,rax
   14000509a:	74 14                	je     1400050b0 <__pformat_xdouble+0x12a>
   14000509c:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   1400050a2:	eb 0c                	jmp    1400050b0 <__pformat_xdouble+0x12a>
   1400050a4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050a8:	66 2d fc 3f          	sub    ax,0x3ffc
   1400050ac:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400050b0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050b4:	48 c1 e8 03          	shr    rax,0x3
   1400050b8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400050bc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400050c0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400050c4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400050c8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400050cc:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400050d0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400050d4:	48 89 c1             	mov    rcx,rax
   1400050d7:	e8 b4 f8 ff ff       	call   140004990 <__pformat_emit_xfloat>
   1400050dc:	90                   	nop
   1400050dd:	48 83 c4 60          	add    rsp,0x60
   1400050e1:	5d                   	pop    rbp
   1400050e2:	c3                   	ret

00000001400050e3 <__mingw_pformat>:
   1400050e3:	55                   	push   rbp
   1400050e4:	48 89 e5             	mov    rbp,rsp
   1400050e7:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   1400050ee:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400050f1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400050f5:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   1400050f9:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   1400050fd:	e8 a6 44 00 00       	call   1400095a8 <_errno>
   140005102:	8b 00                	mov    eax,DWORD PTR [rax]
   140005104:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140005107:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000510b:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   14000510f:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005116:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005119:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000511c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005123:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000512a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005131:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005137:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000513e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005144:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000514b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000514e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005151:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005158:	e9 27 0c 00 00       	jmp    140005d84 <__mingw_pformat+0xca1>
   14000515d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005161:	0f 85 0f 0c 00 00    	jne    140005d76 <__mingw_pformat+0xc93>
   140005167:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000516e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005175:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005179:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000517d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005181:	48 83 c0 0c          	add    rax,0xc
   140005185:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005189:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000518c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000518f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005196:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140005199:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000519c:	e9 c4 0b 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   1400051a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400051a5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400051a9:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400051ad:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400051b0:	0f be c0             	movsx  eax,al
   1400051b3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400051b6:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051ba:	0f 84 94 09 00 00    	je     140005b54 <__mingw_pformat+0xa71>
   1400051c0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400051c4:	0f 8f 02 0b 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400051ca:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400051ce:	0f 84 eb 03 00 00    	je     1400055bf <__mingw_pformat+0x4dc>
   1400051d4:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400051d8:	0f 8f ee 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400051de:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400051e2:	0f 84 31 09 00 00    	je     140005b19 <__mingw_pformat+0xa36>
   1400051e8:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400051ec:	0f 8f da 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400051f2:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   1400051f6:	0f 84 c3 03 00 00    	je     1400055bf <__mingw_pformat+0x4dc>
   1400051fc:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005200:	0f 8f c6 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005206:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   14000520a:	0f 84 31 09 00 00    	je     140005b41 <__mingw_pformat+0xa5e>
   140005210:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005214:	0f 8f b2 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000521a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000521e:	0f 84 31 03 00 00    	je     140005555 <__mingw_pformat+0x472>
   140005224:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005228:	0f 8f 9e 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000522e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005232:	0f 84 28 05 00 00    	je     140005760 <__mingw_pformat+0x67d>
   140005238:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000523c:	0f 8f 8a 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005242:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005246:	0f 84 73 03 00 00    	je     1400055bf <__mingw_pformat+0x4dc>
   14000524c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005250:	0f 8f 76 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005256:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000525a:	0f 84 4d 07 00 00    	je     1400059ad <__mingw_pformat+0x8ca>
   140005260:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005264:	0f 8f 62 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000526a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000526e:	0f 84 2d 03 00 00    	je     1400055a1 <__mingw_pformat+0x4be>
   140005274:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005278:	0f 8f 4e 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000527e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005282:	0f 84 65 08 00 00    	je     140005aed <__mingw_pformat+0xa0a>
   140005288:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000528c:	0f 8f 3a 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005292:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   140005296:	0f 84 db 07 00 00    	je     140005a77 <__mingw_pformat+0x994>
   14000529c:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400052a0:	0f 8f 26 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400052a6:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400052aa:	0f 84 ee 03 00 00    	je     14000569e <__mingw_pformat+0x5bb>
   1400052b0:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400052b4:	0f 8f 12 0a 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400052ba:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052be:	0f 84 87 07 00 00    	je     140005a4b <__mingw_pformat+0x968>
   1400052c4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400052c8:	0f 8f fe 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400052ce:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400052d2:	0f 84 f3 05 00 00    	je     1400058cb <__mingw_pformat+0x7e8>
   1400052d8:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400052dc:	0f 8f ea 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400052e2:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400052e6:	0f 84 61 05 00 00    	je     14000584d <__mingw_pformat+0x76a>
   1400052ec:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400052f0:	0f 8f d6 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400052f6:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   1400052fa:	0f 84 cf 04 00 00    	je     1400057cf <__mingw_pformat+0x6ec>
   140005300:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   140005304:	0f 8f c2 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000530a:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   14000530e:	0f 84 8a 03 00 00    	je     14000569e <__mingw_pformat+0x5bb>
   140005314:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005318:	0f 8f ae 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000531e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005322:	0f 84 b5 01 00 00    	je     1400054dd <__mingw_pformat+0x3fa>
   140005328:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000532c:	0f 8f 9a 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005332:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005336:	0f 84 83 02 00 00    	je     1400055bf <__mingw_pformat+0x4dc>
   14000533c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005340:	0f 8f 86 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005346:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000534a:	0f 84 f9 05 00 00    	je     140005949 <__mingw_pformat+0x866>
   140005350:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005354:	0f 8f 72 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000535a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000535e:	0f 84 5b 02 00 00    	je     1400055bf <__mingw_pformat+0x4dc>
   140005364:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005368:	0f 8f 5e 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000536e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005372:	0f 84 d6 01 00 00    	je     14000554e <__mingw_pformat+0x46b>
   140005378:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000537c:	0f 8f 4a 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005382:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005386:	0f 84 a0 07 00 00    	je     140005b2c <__mingw_pformat+0xa49>
   14000538c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005390:	0f 8f 36 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005396:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   14000539a:	0f 84 ea 06 00 00    	je     140005a8a <__mingw_pformat+0x9a7>
   1400053a0:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400053a4:	0f 8f 22 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400053aa:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400053ae:	0f 84 20 05 00 00    	je     1400058d4 <__mingw_pformat+0x7f1>
   1400053b4:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400053b8:	0f 8f 0e 09 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400053be:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053c2:	0f 84 8e 04 00 00    	je     140005856 <__mingw_pformat+0x773>
   1400053c8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400053cc:	0f 8f fa 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400053d2:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400053d6:	0f 84 fc 03 00 00    	je     1400057d8 <__mingw_pformat+0x6f5>
   1400053dc:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400053e0:	0f 8f e6 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400053e6:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400053ea:	0f 84 e6 00 00 00    	je     1400054d6 <__mingw_pformat+0x3f3>
   1400053f0:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400053f4:	0f 8f d2 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400053fa:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   1400053fe:	0f 84 bb 01 00 00    	je     1400055bf <__mingw_pformat+0x4dc>
   140005404:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   140005408:	0f 8f be 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000540e:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005412:	0f 84 3a 05 00 00    	je     140005952 <__mingw_pformat+0x86f>
   140005418:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000541c:	0f 8f aa 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005422:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005426:	0f 84 8c 08 00 00    	je     140005cb8 <__mingw_pformat+0xbd5>
   14000542c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005430:	0f 8f 96 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005436:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000543a:	0f 84 27 07 00 00    	je     140005b67 <__mingw_pformat+0xa84>
   140005440:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005444:	0f 8f 82 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000544a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000544e:	0f 84 db 07 00 00    	je     140005c2f <__mingw_pformat+0xb4c>
   140005454:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005458:	0f 8f 6e 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000545e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005462:	0f 84 af 07 00 00    	je     140005c17 <__mingw_pformat+0xb34>
   140005468:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000546c:	0f 8f 5a 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005472:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005476:	0f 84 1c 07 00 00    	je     140005b98 <__mingw_pformat+0xab5>
   14000547c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005480:	0f 8f 46 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   140005486:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000548a:	0f 84 b7 07 00 00    	je     140005c47 <__mingw_pformat+0xb64>
   140005490:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   140005494:	0f 8f 32 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   14000549a:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   14000549e:	74 23                	je     1400054c3 <__mingw_pformat+0x3e0>
   1400054a0:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400054a4:	0f 8f 22 08 00 00    	jg     140005ccc <__mingw_pformat+0xbe9>
   1400054aa:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   1400054ae:	0f 84 ec 07 00 00    	je     140005ca0 <__mingw_pformat+0xbbd>
   1400054b4:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   1400054b8:	0f 84 41 07 00 00    	je     140005bff <__mingw_pformat+0xb1c>
   1400054be:	e9 09 08 00 00       	jmp    140005ccc <__mingw_pformat+0xbe9>
   1400054c3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400054c7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400054ca:	89 c1                	mov    ecx,eax
   1400054cc:	e8 7f dc ff ff       	call   140003150 <__pformat_putc>
   1400054d1:	e9 82 fc ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400054d6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400054dd:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400054e4:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400054e8:	74 06                	je     1400054f0 <__mingw_pformat+0x40d>
   1400054ea:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400054ee:	75 30                	jne    140005520 <__mingw_pformat+0x43d>
   1400054f0:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400054f4:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400054f8:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400054fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400054fe:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   140005502:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005506:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   14000550a:	49 89 d0             	mov    r8,rdx
   14000550d:	ba 01 00 00 00       	mov    edx,0x1
   140005512:	48 89 c1             	mov    rcx,rax
   140005515:	e8 3f de ff ff       	call   140003359 <__pformat_wputchars>
   14000551a:	90                   	nop
   14000551b:	e9 38 fc ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005520:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005524:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005528:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000552c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000552e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005531:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005535:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005539:	49 89 d0             	mov    r8,rdx
   14000553c:	ba 01 00 00 00       	mov    edx,0x1
   140005541:	48 89 c1             	mov    rcx,rax
   140005544:	e8 8b dc ff ff       	call   1400031d4 <__pformat_putchars>
   140005549:	e9 0a fc ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   14000554e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005555:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005559:	74 06                	je     140005561 <__mingw_pformat+0x47e>
   14000555b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000555f:	75 20                	jne    140005581 <__mingw_pformat+0x49e>
   140005561:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005565:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005569:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000556d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005570:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005574:	48 89 c1             	mov    rcx,rax
   140005577:	e8 29 df ff ff       	call   1400034a5 <__pformat_wcputs>
   14000557c:	e9 d7 fb ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005581:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005585:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005589:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000558d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005590:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005594:	48 89 c1             	mov    rcx,rax
   140005597:	e8 37 dd ff ff       	call   1400032d3 <__pformat_puts>
   14000559c:	e9 b7 fb ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400055a1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400055a4:	89 c1                	mov    ecx,eax
   1400055a6:	e8 8d 40 00 00       	call   140009638 <strerror>
   1400055ab:	48 89 c1             	mov    rcx,rax
   1400055ae:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400055b2:	48 89 c2             	mov    rdx,rax
   1400055b5:	e8 19 dd ff ff       	call   1400032d3 <__pformat_puts>
   1400055ba:	e9 99 fb ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400055bf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400055c2:	80 e4 fe             	and    ah,0xfe
   1400055c5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400055c8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055cc:	75 15                	jne    1400055e3 <__mingw_pformat+0x500>
   1400055ce:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055d2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055d6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055da:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400055dd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400055e1:	eb 54                	jmp    140005637 <__mingw_pformat+0x554>
   1400055e3:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055e7:	75 16                	jne    1400055ff <__mingw_pformat+0x51c>
   1400055e9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400055ed:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400055f1:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400055f5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400055f7:	89 c0                	mov    eax,eax
   1400055f9:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400055fd:	eb 38                	jmp    140005637 <__mingw_pformat+0x554>
   1400055ff:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005603:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005607:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000560b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000560d:	89 c0                	mov    eax,eax
   14000560f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005613:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005617:	75 0d                	jne    140005626 <__mingw_pformat+0x543>
   140005619:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000561d:	0f b7 c0             	movzx  eax,ax
   140005620:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005624:	eb 11                	jmp    140005637 <__mingw_pformat+0x554>
   140005626:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000562a:	75 0b                	jne    140005637 <__mingw_pformat+0x554>
   14000562c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005630:	0f b6 c0             	movzx  eax,al
   140005633:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005637:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000563b:	75 2e                	jne    14000566b <__mingw_pformat+0x588>
   14000563d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005641:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005645:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000564c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005653:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005657:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000565e:	48 89 c1             	mov    rcx,rax
   140005661:	e8 55 df ff ff       	call   1400035bb <__pformat_int>
   140005666:	e9 ed fa ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   14000566b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000566f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005673:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000567a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005681:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005685:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000568c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000568f:	49 89 c8             	mov    r8,rcx
   140005692:	89 c1                	mov    ecx,eax
   140005694:	e8 a5 e2 ff ff       	call   14000393e <__pformat_xint>
   140005699:	e9 ba fa ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   14000569e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400056a1:	0c 80                	or     al,0x80
   1400056a3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400056a6:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400056aa:	75 15                	jne    1400056c1 <__mingw_pformat+0x5de>
   1400056ac:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056b0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056b4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056b8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056bb:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056bf:	eb 56                	jmp    140005717 <__mingw_pformat+0x634>
   1400056c1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056c5:	75 16                	jne    1400056dd <__mingw_pformat+0x5fa>
   1400056c7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056cb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056cf:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056d3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056d5:	48 98                	cdqe
   1400056d7:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056db:	eb 3a                	jmp    140005717 <__mingw_pformat+0x634>
   1400056dd:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056e1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056e5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056e9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400056eb:	48 98                	cdqe
   1400056ed:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056f1:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400056f5:	75 0e                	jne    140005705 <__mingw_pformat+0x622>
   1400056f7:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   1400056fb:	48 0f bf c0          	movsx  rax,ax
   1400056ff:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005703:	eb 12                	jmp    140005717 <__mingw_pformat+0x634>
   140005705:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005709:	75 0c                	jne    140005717 <__mingw_pformat+0x634>
   14000570b:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   14000570f:	48 0f be c0          	movsx  rax,al
   140005713:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005717:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000571b:	48 85 c0             	test   rax,rax
   14000571e:	79 09                	jns    140005729 <__mingw_pformat+0x646>
   140005720:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005727:	eb 05                	jmp    14000572e <__mingw_pformat+0x64b>
   140005729:	b8 00 00 00 00       	mov    eax,0x0
   14000572e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005732:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005736:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000573a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005741:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005748:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000574c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005753:	48 89 c1             	mov    rcx,rax
   140005756:	e8 60 de ff ff       	call   1400035bb <__pformat_int>
   14000575b:	e9 f8 f9 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005760:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005764:	75 18                	jne    14000577e <__mingw_pformat+0x69b>
   140005766:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005769:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000576c:	75 10                	jne    14000577e <__mingw_pformat+0x69b>
   14000576e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005771:	80 cc 02             	or     ah,0x2
   140005774:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005777:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000577e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005782:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005786:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000578a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000578d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005791:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   140005798:	00 
   140005799:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000579d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400057a1:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400057a8:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400057af:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057b3:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400057ba:	49 89 d0             	mov    r8,rdx
   1400057bd:	48 89 c2             	mov    rdx,rax
   1400057c0:	b9 78 00 00 00       	mov    ecx,0x78
   1400057c5:	e8 74 e1 ff ff       	call   14000393e <__pformat_xint>
   1400057ca:	e9 89 f9 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400057cf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057d2:	83 c8 20             	or     eax,0x20
   1400057d5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057d8:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057db:	83 e0 04             	and    eax,0x4
   1400057de:	85 c0                	test   eax,eax
   1400057e0:	74 2f                	je     140005811 <__mingw_pformat+0x72e>
   1400057e2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057e6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057ea:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057ee:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400057f1:	db 28                	fld    TBYTE PTR [rax]
   1400057f3:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400057f9:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400057fd:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005804:	48 89 c1             	mov    rcx,rax
   140005807:	e8 1d ef ff ff       	call   140004729 <__pformat_efloat>
   14000580c:	e9 47 f9 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005811:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005815:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005819:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000581d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005821:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005828:	ff 
   140005829:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000582f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005835:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005839:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005840:	48 89 c1             	mov    rcx,rax
   140005843:	e8 e1 ee ff ff       	call   140004729 <__pformat_efloat>
   140005848:	e9 0b f9 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   14000584d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005850:	83 c8 20             	or     eax,0x20
   140005853:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005856:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005859:	83 e0 04             	and    eax,0x4
   14000585c:	85 c0                	test   eax,eax
   14000585e:	74 2f                	je     14000588f <__mingw_pformat+0x7ac>
   140005860:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005864:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005868:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000586c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000586f:	db 28                	fld    TBYTE PTR [rax]
   140005871:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005877:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000587b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005882:	48 89 c1             	mov    rcx,rax
   140005885:	e8 cf ed ff ff       	call   140004659 <__pformat_float>
   14000588a:	e9 c9 f8 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   14000588f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005893:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005897:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000589b:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   14000589f:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   1400058a6:	ff 
   1400058a7:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400058ad:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058b3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058b7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400058be:	48 89 c1             	mov    rcx,rax
   1400058c1:	e8 93 ed ff ff       	call   140004659 <__pformat_float>
   1400058c6:	e9 8d f8 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400058cb:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058ce:	83 c8 20             	or     eax,0x20
   1400058d1:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058d4:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058d7:	83 e0 04             	and    eax,0x4
   1400058da:	85 c0                	test   eax,eax
   1400058dc:	74 2f                	je     14000590d <__mingw_pformat+0x82a>
   1400058de:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058e2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058e6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058ea:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400058ed:	db 28                	fld    TBYTE PTR [rax]
   1400058ef:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400058f5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058f9:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005900:	48 89 c1             	mov    rcx,rax
   140005903:	e8 cc ee ff ff       	call   1400047d4 <__pformat_gfloat>
   140005908:	e9 4b f8 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   14000590d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005911:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005915:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005919:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   14000591d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005924:	ff 
   140005925:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000592b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005931:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005935:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000593c:	48 89 c1             	mov    rcx,rax
   14000593f:	e8 90 ee ff ff       	call   1400047d4 <__pformat_gfloat>
   140005944:	e9 0f f8 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005949:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   14000594c:	83 c8 20             	or     eax,0x20
   14000594f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005952:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005955:	83 e0 04             	and    eax,0x4
   140005958:	85 c0                	test   eax,eax
   14000595a:	74 2f                	je     14000598b <__mingw_pformat+0x8a8>
   14000595c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005960:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005964:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005968:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000596b:	db 28                	fld    TBYTE PTR [rax]
   14000596d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005973:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005977:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   14000597e:	48 89 c1             	mov    rcx,rax
   140005981:	e8 e7 f4 ff ff       	call   140004e6d <__pformat_xldouble>
   140005986:	e9 cd f7 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   14000598b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000598f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005993:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005997:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000599a:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000599e:	66 48 0f 6e c0       	movq   xmm0,rax
   1400059a3:	e8 de f5 ff ff       	call   140004f86 <__pformat_xdouble>
   1400059a8:	e9 ab f7 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400059ad:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   1400059b1:	75 1b                	jne    1400059ce <__mingw_pformat+0x8eb>
   1400059b3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   1400059b6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059ba:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059be:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059c2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059c5:	89 ca                	mov    edx,ecx
   1400059c7:	88 10                	mov    BYTE PTR [rax],dl
   1400059c9:	e9 8a f7 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400059ce:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   1400059d2:	75 1c                	jne    1400059f0 <__mingw_pformat+0x90d>
   1400059d4:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   1400059d7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059db:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059df:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059e3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059e6:	89 ca                	mov    edx,ecx
   1400059e8:	66 89 10             	mov    WORD PTR [rax],dx
   1400059eb:	e9 68 f7 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   1400059f0:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400059f4:	75 19                	jne    140005a0f <__mingw_pformat+0x92c>
   1400059f6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059fa:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059fe:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a02:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a05:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a08:	89 10                	mov    DWORD PTR [rax],edx
   140005a0a:	e9 49 f7 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005a0f:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005a13:	75 1d                	jne    140005a32 <__mingw_pformat+0x94f>
   140005a15:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005a18:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a1c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a20:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a24:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a27:	48 63 d1             	movsxd rdx,ecx
   140005a2a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005a2d:	e9 26 f7 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005a32:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a36:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a3a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a3e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a41:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005a44:	89 10                	mov    DWORD PTR [rax],edx
   140005a46:	e9 0d f7 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005a4b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a4f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005a52:	3c 68                	cmp    al,0x68
   140005a54:	75 0e                	jne    140005a64 <__mingw_pformat+0x981>
   140005a56:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005a5b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005a62:	eb 07                	jmp    140005a6b <__mingw_pformat+0x988>
   140005a64:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005a6b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005a72:	e9 ee 02 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005a77:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005a7e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005a85:	e9 db 02 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005a8a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a8e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005a91:	3c 36                	cmp    al,0x36
   140005a93:	75 1d                	jne    140005ab2 <__mingw_pformat+0x9cf>
   140005a95:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005a99:	48 83 c0 01          	add    rax,0x1
   140005a9d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005aa0:	3c 34                	cmp    al,0x34
   140005aa2:	75 0e                	jne    140005ab2 <__mingw_pformat+0x9cf>
   140005aa4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005aab:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005ab0:	eb 2f                	jmp    140005ae1 <__mingw_pformat+0x9fe>
   140005ab2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ab6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ab9:	3c 33                	cmp    al,0x33
   140005abb:	75 1d                	jne    140005ada <__mingw_pformat+0x9f7>
   140005abd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ac1:	48 83 c0 01          	add    rax,0x1
   140005ac5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ac8:	3c 32                	cmp    al,0x32
   140005aca:	75 0e                	jne    140005ada <__mingw_pformat+0x9f7>
   140005acc:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005ad3:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005ad8:	eb 07                	jmp    140005ae1 <__mingw_pformat+0x9fe>
   140005ada:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005ae1:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ae8:	e9 78 02 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005aed:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005af1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005af4:	3c 6c                	cmp    al,0x6c
   140005af6:	75 0e                	jne    140005b06 <__mingw_pformat+0xa23>
   140005af8:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005afd:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b04:	eb 07                	jmp    140005b0d <__mingw_pformat+0xa2a>
   140005b06:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b0d:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b14:	e9 4c 02 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005b19:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005b20:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b27:	e9 39 02 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005b2c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005b2f:	83 c8 04             	or     eax,0x4
   140005b32:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005b35:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b3c:	e9 24 02 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005b41:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b48:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b4f:	e9 11 02 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005b54:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b5b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b62:	e9 fe 01 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005b67:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005b6b:	77 1f                	ja     140005b8c <__mingw_pformat+0xaa9>
   140005b6d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005b74:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005b78:	48 83 c0 10          	add    rax,0x10
   140005b7c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005b80:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005b87:	e9 d9 01 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005b8c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b93:	e9 cd 01 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005b98:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005b9d:	74 4c                	je     140005beb <__mingw_pformat+0xb08>
   140005b9f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ba3:	74 06                	je     140005bab <__mingw_pformat+0xac8>
   140005ba5:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005ba9:	75 40                	jne    140005beb <__mingw_pformat+0xb08>
   140005bab:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005baf:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005bb3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005bb7:	8b 10                	mov    edx,DWORD PTR [rax]
   140005bb9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bbd:	89 10                	mov    DWORD PTR [rax],edx
   140005bbf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005bc3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005bc5:	85 c0                	test   eax,eax
   140005bc7:	79 29                	jns    140005bf2 <__mingw_pformat+0xb0f>
   140005bc9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005bcd:	75 13                	jne    140005be2 <__mingw_pformat+0xaff>
   140005bcf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005bd2:	80 cc 04             	or     ah,0x4
   140005bd5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005bd8:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005bdb:	f7 d8                	neg    eax
   140005bdd:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005be0:	eb 10                	jmp    140005bf2 <__mingw_pformat+0xb0f>
   140005be2:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005be9:	eb 07                	jmp    140005bf2 <__mingw_pformat+0xb0f>
   140005beb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bf2:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005bf9:	00 
   140005bfa:	e9 66 01 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005bff:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c03:	0f 85 4f 01 00 00    	jne    140005d58 <__mingw_pformat+0xc75>
   140005c09:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c0c:	80 cc 08             	or     ah,0x8
   140005c0f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c12:	e9 41 01 00 00       	jmp    140005d58 <__mingw_pformat+0xc75>
   140005c17:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c1b:	0f 85 3a 01 00 00    	jne    140005d5b <__mingw_pformat+0xc78>
   140005c21:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c24:	80 cc 01             	or     ah,0x1
   140005c27:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c2a:	e9 2c 01 00 00       	jmp    140005d5b <__mingw_pformat+0xc78>
   140005c2f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c33:	0f 85 25 01 00 00    	jne    140005d5e <__mingw_pformat+0xc7b>
   140005c39:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c3c:	80 cc 04             	or     ah,0x4
   140005c3f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c42:	e9 17 01 00 00       	jmp    140005d5e <__mingw_pformat+0xc7b>
   140005c47:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005c4b:	0f 85 10 01 00 00    	jne    140005d61 <__mingw_pformat+0xc7e>
   140005c51:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c54:	80 cc 10             	or     ah,0x10
   140005c57:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c5a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005c61:	00 
   140005c62:	e8 a9 39 00 00       	call   140009610 <localeconv>
   140005c67:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005c6b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005c6f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005c73:	49 89 c9             	mov    r9,rcx
   140005c76:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005c7c:	48 89 c1             	mov    rcx,rax
   140005c7f:	e8 bc 33 00 00       	call   140009040 <mbrtowc>
   140005c84:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005c87:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005c8b:	7e 08                	jle    140005c95 <__mingw_pformat+0xbb2>
   140005c8d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005c91:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005c95:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005c98:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005c9b:	e9 c1 00 00 00       	jmp    140005d61 <__mingw_pformat+0xc7e>
   140005ca0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ca4:	0f 85 ba 00 00 00    	jne    140005d64 <__mingw_pformat+0xc81>
   140005caa:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cad:	83 c8 40             	or     eax,0x40
   140005cb0:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cb3:	e9 ac 00 00 00       	jmp    140005d64 <__mingw_pformat+0xc81>
   140005cb8:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cbc:	75 0e                	jne    140005ccc <__mingw_pformat+0xbe9>
   140005cbe:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005cc1:	80 cc 02             	or     ah,0x2
   140005cc4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005cc7:	e9 99 00 00 00       	jmp    140005d65 <__mingw_pformat+0xc82>
   140005ccc:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005cd0:	77 68                	ja     140005d3a <__mingw_pformat+0xc57>
   140005cd2:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005cd6:	7f 62                	jg     140005d3a <__mingw_pformat+0xc57>
   140005cd8:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005cdc:	7e 5c                	jle    140005d3a <__mingw_pformat+0xc57>
   140005cde:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005ce2:	75 09                	jne    140005ced <__mingw_pformat+0xc0a>
   140005ce4:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005ceb:	eb 0d                	jmp    140005cfa <__mingw_pformat+0xc17>
   140005ced:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005cf1:	75 07                	jne    140005cfa <__mingw_pformat+0xc17>
   140005cf3:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005cfa:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005cff:	74 64                	je     140005d65 <__mingw_pformat+0xc82>
   140005d01:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d05:	8b 00                	mov    eax,DWORD PTR [rax]
   140005d07:	85 c0                	test   eax,eax
   140005d09:	79 0e                	jns    140005d19 <__mingw_pformat+0xc36>
   140005d0b:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d0e:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d15:	89 10                	mov    DWORD PTR [rax],edx
   140005d17:	eb 4c                	jmp    140005d65 <__mingw_pformat+0xc82>
   140005d19:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d1d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005d1f:	89 d0                	mov    eax,edx
   140005d21:	c1 e0 02             	shl    eax,0x2
   140005d24:	01 d0                	add    eax,edx
   140005d26:	01 c0                	add    eax,eax
   140005d28:	89 c2                	mov    edx,eax
   140005d2a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d2d:	01 d0                	add    eax,edx
   140005d2f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005d32:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005d36:	89 10                	mov    DWORD PTR [rax],edx
   140005d38:	eb 2b                	jmp    140005d65 <__mingw_pformat+0xc82>
   140005d3a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005d3e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005d42:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005d46:	48 89 c2             	mov    rdx,rax
   140005d49:	b9 25 00 00 00       	mov    ecx,0x25
   140005d4e:	e8 fd d3 ff ff       	call   140003150 <__pformat_putc>
   140005d53:	e9 00 f4 ff ff       	jmp    140005158 <__mingw_pformat+0x75>
   140005d58:	90                   	nop
   140005d59:	eb 0a                	jmp    140005d65 <__mingw_pformat+0xc82>
   140005d5b:	90                   	nop
   140005d5c:	eb 07                	jmp    140005d65 <__mingw_pformat+0xc82>
   140005d5e:	90                   	nop
   140005d5f:	eb 04                	jmp    140005d65 <__mingw_pformat+0xc82>
   140005d61:	90                   	nop
   140005d62:	eb 01                	jmp    140005d65 <__mingw_pformat+0xc82>
   140005d64:	90                   	nop
   140005d65:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005d69:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005d6c:	84 c0                	test   al,al
   140005d6e:	0f 85 2d f4 ff ff    	jne    1400051a1 <__mingw_pformat+0xbe>
   140005d74:	eb 0e                	jmp    140005d84 <__mingw_pformat+0xca1>
   140005d76:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005d7a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005d7d:	89 c1                	mov    ecx,eax
   140005d7f:	e8 cc d3 ff ff       	call   140003150 <__pformat_putc>
   140005d84:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005d88:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005d8c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005d90:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005d93:	0f be c0             	movsx  eax,al
   140005d96:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005d99:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005d9d:	0f 85 ba f3 ff ff    	jne    14000515d <__mingw_pformat+0x7a>
   140005da3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005da6:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005dad:	5d                   	pop    rbp
   140005dae:	c3                   	ret
   140005daf:	90                   	nop

0000000140005db0 <__rv_alloc_D2A>:
   140005db0:	55                   	push   rbp
   140005db1:	48 89 e5             	mov    rbp,rsp
   140005db4:	48 83 ec 30          	sub    rsp,0x30
   140005db8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005dbb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005dc2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005dc9:	eb 07                	jmp    140005dd2 <__rv_alloc_D2A+0x22>
   140005dcb:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005dcf:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005dd2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005dd5:	83 c0 17             	add    eax,0x17
   140005dd8:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005ddb:	7f ee                	jg     140005dcb <__rv_alloc_D2A+0x1b>
   140005ddd:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005de0:	89 c1                	mov    ecx,eax
   140005de2:	e8 56 1e 00 00       	call   140007c3d <__Balloc_D2A>
   140005de7:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005deb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005def:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005df2:	89 10                	mov    DWORD PTR [rax],edx
   140005df4:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005df8:	48 83 c0 04          	add    rax,0x4
   140005dfc:	48 83 c4 30          	add    rsp,0x30
   140005e00:	5d                   	pop    rbp
   140005e01:	c3                   	ret

0000000140005e02 <__nrv_alloc_D2A>:
   140005e02:	55                   	push   rbp
   140005e03:	48 89 e5             	mov    rbp,rsp
   140005e06:	48 83 ec 30          	sub    rsp,0x30
   140005e0a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e0e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005e12:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005e16:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005e19:	89 c1                	mov    ecx,eax
   140005e1b:	e8 90 ff ff ff       	call   140005db0 <__rv_alloc_D2A>
   140005e20:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005e24:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e28:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e2c:	eb 05                	jmp    140005e33 <__nrv_alloc_D2A+0x31>
   140005e2e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005e33:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e37:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e3b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005e3f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005e42:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e46:	88 10                	mov    BYTE PTR [rax],dl
   140005e48:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e4c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e4f:	84 c0                	test   al,al
   140005e51:	75 db                	jne    140005e2e <__nrv_alloc_D2A+0x2c>
   140005e53:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005e58:	74 0b                	je     140005e65 <__nrv_alloc_D2A+0x63>
   140005e5a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005e5e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005e62:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005e65:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e69:	48 83 c4 30          	add    rsp,0x30
   140005e6d:	5d                   	pop    rbp
   140005e6e:	c3                   	ret

0000000140005e6f <__freedtoa>:
   140005e6f:	55                   	push   rbp
   140005e70:	48 89 e5             	mov    rbp,rsp
   140005e73:	48 83 ec 30          	sub    rsp,0x30
   140005e77:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005e7b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005e7f:	48 83 e8 04          	sub    rax,0x4
   140005e83:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005e87:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e8b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005e8d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e91:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005e94:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005e98:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005e9b:	ba 01 00 00 00       	mov    edx,0x1
   140005ea0:	89 c1                	mov    ecx,eax
   140005ea2:	d3 e2                	shl    edx,cl
   140005ea4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005ea8:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005eab:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005eaf:	48 89 c1             	mov    rcx,rax
   140005eb2:	e8 c7 1e 00 00       	call   140007d7e <__Bfree_D2A>
   140005eb7:	90                   	nop
   140005eb8:	48 83 c4 30          	add    rsp,0x30
   140005ebc:	5d                   	pop    rbp
   140005ebd:	c3                   	ret

0000000140005ebe <__quorem_D2A>:
   140005ebe:	55                   	push   rbp
   140005ebf:	48 89 e5             	mov    rbp,rsp
   140005ec2:	48 83 ec 70          	sub    rsp,0x70
   140005ec6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005eca:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005ece:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ed2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005ed5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005ed8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005edc:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005edf:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005ee2:	7e 0a                	jle    140005eee <__quorem_D2A+0x30>
   140005ee4:	b8 00 00 00 00       	mov    eax,0x0
   140005ee9:	e9 3f 02 00 00       	jmp    14000612d <__quorem_D2A+0x26f>
   140005eee:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005ef2:	48 83 c0 18          	add    rax,0x18
   140005ef6:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140005efa:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005efe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f01:	48 98                	cdqe
   140005f03:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f0a:	00 
   140005f0b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f0f:	48 01 d0             	add    rax,rdx
   140005f12:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140005f16:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f1a:	48 83 c0 18          	add    rax,0x18
   140005f1e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f22:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005f25:	48 98                	cdqe
   140005f27:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140005f2e:	00 
   140005f2f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f33:	48 01 d0             	add    rax,rdx
   140005f36:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140005f3a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005f3e:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f40:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140005f44:	8b 12                	mov    edx,DWORD PTR [rdx]
   140005f46:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140005f49:	ba 00 00 00 00       	mov    edx,0x0
   140005f4e:	f7 f1                	div    ecx
   140005f50:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140005f53:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140005f57:	0f 84 c4 00 00 00    	je     140006021 <__quorem_D2A+0x163>
   140005f5d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140005f64:	00 
   140005f65:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   140005f6c:	00 
   140005f6d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005f71:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005f75:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140005f79:	8b 00                	mov    eax,DWORD PTR [rax]
   140005f7b:	89 c2                	mov    edx,eax
   140005f7d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140005f80:	48 0f af d0          	imul   rdx,rax
   140005f84:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140005f88:	48 01 d0             	add    rax,rdx
   140005f8b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140005f8f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005f93:	48 c1 e8 20          	shr    rax,0x20
   140005f97:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140005f9b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f9f:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fa1:	89 c1                	mov    ecx,eax
   140005fa3:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140005fa7:	89 c2                	mov    edx,eax
   140005fa9:	48 89 c8             	mov    rax,rcx
   140005fac:	48 29 d0             	sub    rax,rdx
   140005faf:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   140005fb3:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140005fb7:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140005fbb:	48 c1 e8 20          	shr    rax,0x20
   140005fbf:	83 e0 01             	and    eax,0x1
   140005fc2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140005fc6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005fca:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140005fce:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140005fd2:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140005fd6:	89 10                	mov    DWORD PTR [rax],edx
   140005fd8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140005fdc:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140005fe0:	73 8b                	jae    140005f6d <__quorem_D2A+0xaf>
   140005fe2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140005fe6:	8b 00                	mov    eax,DWORD PTR [rax]
   140005fe8:	85 c0                	test   eax,eax
   140005fea:	75 35                	jne    140006021 <__quorem_D2A+0x163>
   140005fec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005ff0:	48 83 c0 18          	add    rax,0x18
   140005ff4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005ff8:	eb 04                	jmp    140005ffe <__quorem_D2A+0x140>
   140005ffa:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140005ffe:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140006003:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006007:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   14000600b:	73 0a                	jae    140006017 <__quorem_D2A+0x159>
   14000600d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006011:	8b 00                	mov    eax,DWORD PTR [rax]
   140006013:	85 c0                	test   eax,eax
   140006015:	74 e3                	je     140005ffa <__quorem_D2A+0x13c>
   140006017:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000601b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000601e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006021:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006025:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006029:	48 89 c1             	mov    rcx,rax
   14000602c:	e8 bc 24 00 00       	call   1400084ed <__cmp_D2A>
   140006031:	85 c0                	test   eax,eax
   140006033:	0f 88 f1 00 00 00    	js     14000612a <__quorem_D2A+0x26c>
   140006039:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000603d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006044:	00 
   140006045:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000604c:	00 
   14000604d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006051:	48 83 c0 18          	add    rax,0x18
   140006055:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006059:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000605d:	48 83 c0 18          	add    rax,0x18
   140006061:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006065:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006069:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000606d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006071:	8b 00                	mov    eax,DWORD PTR [rax]
   140006073:	89 c2                	mov    edx,eax
   140006075:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006079:	48 01 d0             	add    rax,rdx
   14000607c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006080:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006084:	48 c1 e8 20          	shr    rax,0x20
   140006088:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000608c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006090:	8b 00                	mov    eax,DWORD PTR [rax]
   140006092:	89 c1                	mov    ecx,eax
   140006094:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006098:	89 c2                	mov    edx,eax
   14000609a:	48 89 c8             	mov    rax,rcx
   14000609d:	48 29 d0             	sub    rax,rdx
   1400060a0:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400060a4:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400060a8:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400060ac:	48 c1 e8 20          	shr    rax,0x20
   1400060b0:	83 e0 01             	and    eax,0x1
   1400060b3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060b7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060bb:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060bf:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060c3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060c7:	89 10                	mov    DWORD PTR [rax],edx
   1400060c9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060cd:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400060d1:	73 92                	jae    140006065 <__quorem_D2A+0x1a7>
   1400060d3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400060d7:	48 83 c0 18          	add    rax,0x18
   1400060db:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400060df:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400060e2:	48 98                	cdqe
   1400060e4:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400060eb:	00 
   1400060ec:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060f0:	48 01 d0             	add    rax,rdx
   1400060f3:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400060f7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060fd:	85 c0                	test   eax,eax
   1400060ff:	75 29                	jne    14000612a <__quorem_D2A+0x26c>
   140006101:	eb 04                	jmp    140006107 <__quorem_D2A+0x249>
   140006103:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140006107:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   14000610c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006110:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006114:	73 0a                	jae    140006120 <__quorem_D2A+0x262>
   140006116:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000611a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000611c:	85 c0                	test   eax,eax
   14000611e:	74 e3                	je     140006103 <__quorem_D2A+0x245>
   140006120:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006124:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006127:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000612a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000612d:	48 83 c4 70          	add    rsp,0x70
   140006131:	5d                   	pop    rbp
   140006132:	c3                   	ret
   140006133:	90                   	nop
   140006134:	90                   	nop
   140006135:	90                   	nop
   140006136:	90                   	nop
   140006137:	90                   	nop
   140006138:	90                   	nop
   140006139:	90                   	nop
   14000613a:	90                   	nop
   14000613b:	90                   	nop
   14000613c:	90                   	nop
   14000613d:	90                   	nop
   14000613e:	90                   	nop
   14000613f:	90                   	nop

0000000140006140 <__hi0bits_D2A>:
   140006140:	55                   	push   rbp
   140006141:	48 89 e5             	mov    rbp,rsp
   140006144:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006147:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000614b:	83 f0 1f             	xor    eax,0x1f
   14000614e:	5d                   	pop    rbp
   14000614f:	c3                   	ret

0000000140006150 <bitstob>:
   140006150:	55                   	push   rbp
   140006151:	53                   	push   rbx
   140006152:	48 83 ec 58          	sub    rsp,0x58
   140006156:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000615b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000615f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006162:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006166:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000616d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006174:	eb 07                	jmp    14000617d <bitstob+0x2d>
   140006176:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006179:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000617d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006180:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006183:	7c f1                	jl     140006176 <bitstob+0x26>
   140006185:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006188:	89 c1                	mov    ecx,eax
   14000618a:	e8 ae 1a 00 00       	call   140007c3d <__Balloc_D2A>
   14000618f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006193:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140006196:	83 e8 01             	sub    eax,0x1
   140006199:	c1 f8 05             	sar    eax,0x5
   14000619c:	48 98                	cdqe
   14000619e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400061a5:	00 
   1400061a6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400061aa:	48 01 d0             	add    rax,rdx
   1400061ad:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400061b1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400061b5:	48 83 c0 18          	add    rax,0x18
   1400061b9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400061bd:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061c1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061c5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061c9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400061cd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400061d1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400061d5:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400061d7:	89 10                	mov    DWORD PTR [rax],edx
   1400061d9:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   1400061de:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400061e2:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400061e6:	73 dd                	jae    1400061c5 <bitstob+0x75>
   1400061e8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061ec:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   1400061f0:	48 c1 f8 02          	sar    rax,0x2
   1400061f4:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400061f7:	eb 1d                	jmp    140006216 <bitstob+0xc6>
   1400061f9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400061fd:	75 17                	jne    140006216 <bitstob+0xc6>
   1400061ff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006203:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   14000620a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000620e:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006214:	eb 59                	jmp    14000626f <bitstob+0x11f>
   140006216:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000621a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000621d:	48 98                	cdqe
   14000621f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006226:	00 
   140006227:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000622b:	48 01 d0             	add    rax,rdx
   14000622e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006230:	85 c0                	test   eax,eax
   140006232:	74 c5                	je     1400061f9 <bitstob+0xa9>
   140006234:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006237:	8d 50 01             	lea    edx,[rax+0x1]
   14000623a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000623e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006241:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006244:	83 c0 01             	add    eax,0x1
   140006247:	c1 e0 05             	shl    eax,0x5
   14000624a:	89 c3                	mov    ebx,eax
   14000624c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006250:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006253:	48 63 d2             	movsxd rdx,edx
   140006256:	48 83 c2 04          	add    rdx,0x4
   14000625a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000625e:	89 c1                	mov    ecx,eax
   140006260:	e8 db fe ff ff       	call   140006140 <__hi0bits_D2A>
   140006265:	29 c3                	sub    ebx,eax
   140006267:	89 da                	mov    edx,ebx
   140006269:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000626d:	89 10                	mov    DWORD PTR [rax],edx
   14000626f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006273:	48 83 c4 58          	add    rsp,0x58
   140006277:	5b                   	pop    rbx
   140006278:	5d                   	pop    rbp
   140006279:	c3                   	ret

000000014000627a <__gdtoa>:
   14000627a:	55                   	push   rbp
   14000627b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006282:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006289:	00 
   14000628a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   140006291:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   140006297:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   14000629e:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   1400062a5:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   1400062ac:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062b3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062b5:	83 e0 cf             	and    eax,0xffffffcf
   1400062b8:	89 c2                	mov    edx,eax
   1400062ba:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062c1:	89 10                	mov    DWORD PTR [rax],edx
   1400062c3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400062ca:	8b 00                	mov    eax,DWORD PTR [rax]
   1400062cc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400062cf:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400062d2:	83 e0 07             	and    eax,0x7
   1400062d5:	83 f8 04             	cmp    eax,0x4
   1400062d8:	0f 84 b0 00 00 00    	je     14000638e <__gdtoa+0x114>
   1400062de:	83 f8 04             	cmp    eax,0x4
   1400062e1:	0f 8f d5 00 00 00    	jg     1400063bc <__gdtoa+0x142>
   1400062e7:	83 f8 03             	cmp    eax,0x3
   1400062ea:	74 74                	je     140006360 <__gdtoa+0xe6>
   1400062ec:	83 f8 03             	cmp    eax,0x3
   1400062ef:	0f 8f c7 00 00 00    	jg     1400063bc <__gdtoa+0x142>
   1400062f5:	85 c0                	test   eax,eax
   1400062f7:	0f 84 05 01 00 00    	je     140006402 <__gdtoa+0x188>
   1400062fd:	85 c0                	test   eax,eax
   1400062ff:	0f 88 b7 00 00 00    	js     1400063bc <__gdtoa+0x142>
   140006305:	83 e8 01             	sub    eax,0x1
   140006308:	83 f8 01             	cmp    eax,0x1
   14000630b:	0f 87 ab 00 00 00    	ja     1400063bc <__gdtoa+0x142>
   140006311:	90                   	nop
   140006312:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006319:	8b 00                	mov    eax,DWORD PTR [rax]
   14000631b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000631e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006322:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006325:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000632c:	49 89 c8             	mov    r8,rcx
   14000632f:	48 89 c1             	mov    rcx,rax
   140006332:	e8 19 fe ff ff       	call   140006150 <bitstob>
   140006337:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000633b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006341:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006344:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006348:	48 89 c1             	mov    rcx,rax
   14000634b:	e8 31 16 00 00       	call   140007981 <__trailz_D2A>
   140006350:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006353:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006356:	85 c0                	test   eax,eax
   140006358:	0f 84 8b 00 00 00    	je     1400063e9 <__gdtoa+0x16f>
   14000635e:	eb 66                	jmp    1400063c6 <__gdtoa+0x14c>
   140006360:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006367:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000636d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006374:	48 8d 0d d5 4f 00 00 	lea    rcx,[rip+0x4fd5]        # 14000b350 <.rdata>
   14000637b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006381:	48 89 c2             	mov    rdx,rax
   140006384:	e8 79 fa ff ff       	call   140005e02 <__nrv_alloc_D2A>
   140006389:	e9 4d 14 00 00       	jmp    1400077db <__gdtoa+0x1561>
   14000638e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006395:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000639b:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400063a2:	48 8d 0d b0 4f 00 00 	lea    rcx,[rip+0x4fb0]        # 14000b359 <.rdata+0x9>
   1400063a9:	41 b8 03 00 00 00    	mov    r8d,0x3
   1400063af:	48 89 c2             	mov    rdx,rax
   1400063b2:	e8 4b fa ff ff       	call   140005e02 <__nrv_alloc_D2A>
   1400063b7:	e9 1f 14 00 00       	jmp    1400077db <__gdtoa+0x1561>
   1400063bc:	b8 00 00 00 00       	mov    eax,0x0
   1400063c1:	e9 15 14 00 00       	jmp    1400077db <__gdtoa+0x1561>
   1400063c6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400063c9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063cd:	48 89 c1             	mov    rcx,rax
   1400063d0:	e8 50 14 00 00       	call   140007825 <__rshift_D2A>
   1400063d5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063d8:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   1400063de:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400063e1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400063e4:	29 c2                	sub    edx,eax
   1400063e6:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   1400063e9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063ed:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400063f0:	85 c0                	test   eax,eax
   1400063f2:	75 3d                	jne    140006431 <__gdtoa+0x1b7>
   1400063f4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400063f8:	48 89 c1             	mov    rcx,rax
   1400063fb:	e8 7e 19 00 00       	call   140007d7e <__Bfree_D2A>
   140006400:	eb 01                	jmp    140006403 <__gdtoa+0x189>
   140006402:	90                   	nop
   140006403:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   14000640a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006410:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006417:	48 8d 0d 3f 4f 00 00 	lea    rcx,[rip+0x4f3f]        # 14000b35d <.rdata+0xd>
   14000641e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006424:	48 89 c2             	mov    rdx,rax
   140006427:	e8 d6 f9 ff ff       	call   140005e02 <__nrv_alloc_D2A>
   14000642c:	e9 aa 13 00 00       	jmp    1400077db <__gdtoa+0x1561>
   140006431:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006435:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006439:	48 89 c1             	mov    rcx,rax
   14000643c:	e8 75 23 00 00       	call   1400087b6 <__b2d_D2A>
   140006441:	66 48 0f 7e c0       	movq   rax,xmm0
   140006446:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000644a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000644d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006453:	01 d0                	add    eax,edx
   140006455:	83 e8 01             	sub    eax,0x1
   140006458:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000645b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000645e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006463:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006466:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006469:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000646e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006471:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006476:	f2 0f 10 15 e2 4e 00 	movsd  xmm2,QWORD PTR [rip+0x4ee2]        # 14000b360 <.rdata+0x10>
   14000647d:	00 
   14000647e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006482:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006486:	f2 0f 10 05 da 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4eda]        # 14000b368 <.rdata+0x18>
   14000648d:	00 
   14000648e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006492:	f2 0f 10 05 d6 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4ed6]        # 14000b370 <.rdata+0x20>
   140006499:	00 
   14000649a:	f2 0f 58 c8          	addsd  xmm1,xmm0
   14000649e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064a1:	66 0f ef d2          	pxor   xmm2,xmm2
   1400064a5:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   1400064a9:	f2 0f 10 05 c7 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4ec7]        # 14000b378 <.rdata+0x28>
   1400064b0:	00 
   1400064b1:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   1400064b5:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400064b9:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400064be:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064c1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400064c4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400064c8:	79 03                	jns    1400064cd <__gdtoa+0x253>
   1400064ca:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400064cd:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   1400064d4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400064d8:	7e 23                	jle    1400064fd <__gdtoa+0x283>
   1400064da:	66 0f ef c9          	pxor   xmm1,xmm1
   1400064de:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   1400064e3:	f2 0f 10 05 95 4e 00 	movsd  xmm0,QWORD PTR [rip+0x4e95]        # 14000b380 <.rdata+0x30>
   1400064ea:	00 
   1400064eb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400064ef:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   1400064f4:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400064f8:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400064fd:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006502:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006506:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006509:	66 0f ef c0          	pxor   xmm0,xmm0
   14000650d:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006512:	76 1b                	jbe    14000652f <__gdtoa+0x2b5>
   140006514:	66 0f ef c0          	pxor   xmm0,xmm0
   140006518:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000651d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006522:	7a 07                	jp     14000652b <__gdtoa+0x2b1>
   140006524:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006529:	74 04                	je     14000652f <__gdtoa+0x2b5>
   14000652b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000652f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006536:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006539:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000653c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006542:	01 ca                	add    edx,ecx
   140006544:	83 ea 01             	sub    edx,0x1
   140006547:	c1 e2 14             	shl    edx,0x14
   14000654a:	01 d0                	add    eax,edx
   14000654c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000654f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006553:	78 2e                	js     140006583 <__gdtoa+0x309>
   140006555:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006559:	7f 28                	jg     140006583 <__gdtoa+0x309>
   14000655b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006560:	48 8b 05 19 51 00 00 	mov    rax,QWORD PTR [rip+0x5119]        # 14000b680 <.refptr.__tens_D2A>
   140006567:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000656a:	48 63 d2             	movsxd rdx,edx
   14000656d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006572:	66 0f 2f c1          	comisd xmm0,xmm1
   140006576:	76 04                	jbe    14000657c <__gdtoa+0x302>
   140006578:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000657c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006583:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006586:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006589:	29 c2                	sub    edx,eax
   14000658b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000658e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006591:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006595:	78 0f                	js     1400065a6 <__gdtoa+0x32c>
   140006597:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   14000659e:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400065a1:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   1400065a4:	eb 0f                	jmp    1400065b5 <__gdtoa+0x33b>
   1400065a6:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400065a9:	f7 d8                	neg    eax
   1400065ab:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   1400065ae:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   1400065b5:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400065b9:	78 15                	js     1400065d0 <__gdtoa+0x356>
   1400065bb:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400065c2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065c5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400065c8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065cb:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400065ce:	eb 15                	jmp    1400065e5 <__gdtoa+0x36b>
   1400065d0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065d3:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   1400065d6:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400065d9:	f7 d8                	neg    eax
   1400065db:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   1400065de:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   1400065e5:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400065ec:	78 09                	js     1400065f7 <__gdtoa+0x37d>
   1400065ee:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   1400065f5:	7e 0a                	jle    140006601 <__gdtoa+0x387>
   1400065f7:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   1400065fe:	00 00 00 
   140006601:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   140006608:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   14000660f:	7e 10                	jle    140006621 <__gdtoa+0x3a7>
   140006611:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006618:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000661f:	eb 1b                	jmp    14000663c <__gdtoa+0x3c2>
   140006621:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006624:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006629:	7f 0a                	jg     140006635 <__gdtoa+0x3bb>
   14000662b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000662e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006633:	7d 07                	jge    14000663c <__gdtoa+0x3c2>
   140006635:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000663c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006643:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000664a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000664d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006650:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006657:	0f 84 c5 00 00 00    	je     140006722 <__gdtoa+0x4a8>
   14000665d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006664:	0f 8f e6 00 00 00    	jg     140006750 <__gdtoa+0x4d6>
   14000666a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006671:	74 7e                	je     1400066f1 <__gdtoa+0x477>
   140006673:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000667a:	0f 8f d0 00 00 00    	jg     140006750 <__gdtoa+0x4d6>
   140006680:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006687:	0f 84 8e 00 00 00    	je     14000671b <__gdtoa+0x4a1>
   14000668d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006694:	0f 8f b6 00 00 00    	jg     140006750 <__gdtoa+0x4d6>
   14000669a:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400066a1:	7f 0e                	jg     1400066b1 <__gdtoa+0x437>
   1400066a3:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400066aa:	79 13                	jns    1400066bf <__gdtoa+0x445>
   1400066ac:	e9 9f 00 00 00       	jmp    140006750 <__gdtoa+0x4d6>
   1400066b1:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400066b8:	74 30                	je     1400066ea <__gdtoa+0x470>
   1400066ba:	e9 91 00 00 00       	jmp    140006750 <__gdtoa+0x4d6>
   1400066bf:	66 0f ef c9          	pxor   xmm1,xmm1
   1400066c3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400066c8:	f2 0f 10 05 b8 4c 00 	movsd  xmm0,QWORD PTR [rip+0x4cb8]        # 14000b388 <.rdata+0x38>
   1400066cf:	00 
   1400066d0:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400066d4:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400066d8:	83 c0 03             	add    eax,0x3
   1400066db:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400066de:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   1400066e5:	00 00 00 
   1400066e8:	eb 66                	jmp    140006750 <__gdtoa+0x4d6>
   1400066ea:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   1400066f1:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   1400066f8:	7f 0a                	jg     140006704 <__gdtoa+0x48a>
   1400066fa:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   140006701:	00 00 00 
   140006704:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   14000670a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000670d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006710:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006713:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006716:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006719:	eb 35                	jmp    140006750 <__gdtoa+0x4d6>
   14000671b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006722:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006728:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000672b:	01 d0                	add    eax,edx
   14000672d:	83 c0 01             	add    eax,0x1
   140006730:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006733:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006736:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006739:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000673c:	83 e8 01             	sub    eax,0x1
   14000673f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006742:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006745:	85 c0                	test   eax,eax
   140006747:	7f 07                	jg     140006750 <__gdtoa+0x4d6>
   140006749:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006750:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006753:	89 c1                	mov    ecx,eax
   140006755:	e8 56 f6 ff ff       	call   140005db0 <__rv_alloc_D2A>
   14000675a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000675e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006762:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006766:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000676d:	7f 09                	jg     140006778 <__gdtoa+0x4fe>
   14000676f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006776:	eb 38                	jmp    1400067b0 <__gdtoa+0x536>
   140006778:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000677f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006782:	83 e8 01             	sub    eax,0x1
   140006785:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006788:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000678c:	74 22                	je     1400067b0 <__gdtoa+0x536>
   14000678e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006792:	79 07                	jns    14000679b <__gdtoa+0x521>
   140006794:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   14000679b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000679e:	83 e0 08             	and    eax,0x8
   1400067a1:	85 c0                	test   eax,eax
   1400067a3:	74 0b                	je     1400067b0 <__gdtoa+0x536>
   1400067a5:	b8 03 00 00 00       	mov    eax,0x3
   1400067aa:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   1400067ad:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400067b0:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400067b4:	0f 88 b9 04 00 00    	js     140006c73 <__gdtoa+0x9f9>
   1400067ba:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   1400067be:	0f 8f af 04 00 00    	jg     140006c73 <__gdtoa+0x9f9>
   1400067c4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400067c8:	0f 84 a5 04 00 00    	je     140006c73 <__gdtoa+0x9f9>
   1400067ce:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400067d2:	0f 85 9b 04 00 00    	jne    140006c73 <__gdtoa+0x9f9>
   1400067d8:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400067dc:	0f 85 91 04 00 00    	jne    140006c73 <__gdtoa+0x9f9>
   1400067e2:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   1400067e9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400067ee:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400067f3:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400067f6:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   1400067f9:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   1400067fc:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   1400067ff:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   140006806:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000680a:	0f 8e 98 00 00 00    	jle    1400068a8 <__gdtoa+0x62e>
   140006810:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006813:	83 e0 0f             	and    eax,0xf
   140006816:	89 c2                	mov    edx,eax
   140006818:	48 8b 05 61 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e61]        # 14000b680 <.refptr.__tens_D2A>
   14000681f:	48 63 d2             	movsxd rdx,edx
   140006822:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006827:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000682c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000682f:	c1 f8 04             	sar    eax,0x4
   140006832:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006835:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006838:	83 e0 10             	and    eax,0x10
   14000683b:	85 c0                	test   eax,eax
   14000683d:	74 5e                	je     14000689d <__gdtoa+0x623>
   14000683f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006843:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006848:	48 8b 05 61 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d61]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000684f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006854:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006858:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000685d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006861:	eb 3a                	jmp    14000689d <__gdtoa+0x623>
   140006863:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006866:	83 e0 01             	and    eax,0x1
   140006869:	85 c0                	test   eax,eax
   14000686b:	74 24                	je     140006891 <__gdtoa+0x617>
   14000686d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006871:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006874:	48 8b 05 35 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d35]        # 14000b5b0 <.refptr.__bigtens_D2A>
   14000687b:	48 63 d2             	movsxd rdx,edx
   14000687e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006883:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006888:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000688c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006891:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006894:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006897:	83 c0 01             	add    eax,0x1
   14000689a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000689d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400068a1:	75 c0                	jne    140006863 <__gdtoa+0x5e9>
   1400068a3:	e9 8b 00 00 00       	jmp    140006933 <__gdtoa+0x6b9>
   1400068a8:	f2 0f 10 05 e0 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4ae0]        # 14000b390 <.rdata+0x40>
   1400068af:	00 
   1400068b0:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400068b5:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400068b8:	f7 d8                	neg    eax
   1400068ba:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400068bd:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400068c1:	74 70                	je     140006933 <__gdtoa+0x6b9>
   1400068c3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400068c8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400068cb:	83 e0 0f             	and    eax,0xf
   1400068ce:	89 c2                	mov    edx,eax
   1400068d0:	48 8b 05 a9 4d 00 00 	mov    rax,QWORD PTR [rip+0x4da9]        # 14000b680 <.refptr.__tens_D2A>
   1400068d7:	48 63 d2             	movsxd rdx,edx
   1400068da:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400068df:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400068e3:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400068e8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400068eb:	c1 f8 04             	sar    eax,0x4
   1400068ee:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400068f1:	eb 3a                	jmp    14000692d <__gdtoa+0x6b3>
   1400068f3:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400068f6:	83 e0 01             	and    eax,0x1
   1400068f9:	85 c0                	test   eax,eax
   1400068fb:	74 24                	je     140006921 <__gdtoa+0x6a7>
   1400068fd:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006901:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006906:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006909:	48 8b 05 a0 4c 00 00 	mov    rax,QWORD PTR [rip+0x4ca0]        # 14000b5b0 <.refptr.__bigtens_D2A>
   140006910:	48 63 d2             	movsxd rdx,edx
   140006913:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006918:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000691c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006921:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006924:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006927:	83 c0 01             	add    eax,0x1
   14000692a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000692d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006931:	75 c0                	jne    1400068f3 <__gdtoa+0x679>
   140006933:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006937:	74 47                	je     140006980 <__gdtoa+0x706>
   140006939:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000693e:	f2 0f 10 05 4a 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a4a]        # 14000b390 <.rdata+0x40>
   140006945:	00 
   140006946:	66 0f 2f c1          	comisd xmm0,xmm1
   14000694a:	76 34                	jbe    140006980 <__gdtoa+0x706>
   14000694c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006950:	7e 2e                	jle    140006980 <__gdtoa+0x706>
   140006952:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006956:	0f 8e f5 02 00 00    	jle    140006c51 <__gdtoa+0x9d7>
   14000695c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000695f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006962:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006966:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   14000696b:	f2 0f 10 05 25 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a25]        # 14000b398 <.rdata+0x48>
   140006972:	00 
   140006973:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006977:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000697c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006980:	66 0f ef c9          	pxor   xmm1,xmm1
   140006984:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006989:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   14000698e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006992:	f2 0f 10 05 06 4a 00 	movsd  xmm0,QWORD PTR [rip+0x4a06]        # 14000b3a0 <.rdata+0x50>
   140006999:	00 
   14000699a:	f2 0f 58 c1          	addsd  xmm0,xmm1
   14000699e:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   1400069a3:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400069a6:	2d 00 00 40 03       	sub    eax,0x3400000
   1400069ab:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400069ae:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400069b2:	75 5f                	jne    140006a13 <__gdtoa+0x799>
   1400069b4:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   1400069bb:	00 
   1400069bc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400069c0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400069c4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069c9:	f2 0f 10 0d d7 49 00 	movsd  xmm1,QWORD PTR [rip+0x49d7]        # 14000b3a8 <.rdata+0x58>
   1400069d0:	00 
   1400069d1:	f2 0f 5c c1          	subsd  xmm0,xmm1
   1400069d5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069da:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400069df:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   1400069e4:	66 0f 2f c1          	comisd xmm0,xmm1
   1400069e8:	0f 87 ac 07 00 00    	ja     14000719a <__gdtoa+0xf20>
   1400069ee:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069f3:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   1400069f8:	f3 0f 7e 15 b0 49 00 	movq   xmm2,QWORD PTR [rip+0x49b0]        # 14000b3b0 <.rdata+0x60>
   1400069ff:	00 
   140006a00:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006a04:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a08:	0f 87 6e 07 00 00    	ja     14000717c <__gdtoa+0xf02>
   140006a0e:	e9 42 02 00 00       	jmp    140006c55 <__gdtoa+0x9db>
   140006a13:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006a17:	0f 84 22 01 00 00    	je     140006b3f <__gdtoa+0x8c5>
   140006a1d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006a22:	f2 0f 10 05 96 49 00 	movsd  xmm0,QWORD PTR [rip+0x4996]        # 14000b3c0 <.rdata+0x70>
   140006a29:	00 
   140006a2a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a2e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006a31:	8d 50 ff             	lea    edx,[rax-0x1]
   140006a34:	48 8b 05 45 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c45]        # 14000b680 <.refptr.__tens_D2A>
   140006a3b:	48 63 d2             	movsxd rdx,edx
   140006a3e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006a43:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006a47:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006a4c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a50:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006a55:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006a5c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a61:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006a66:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006a6a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006a6d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a72:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a76:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006a7b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006a80:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006a84:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a89:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006a8c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006a8f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006a93:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006a97:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006a9b:	89 ca                	mov    edx,ecx
   140006a9d:	88 10                	mov    BYTE PTR [rax],dl
   140006a9f:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006aa4:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006aa9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006aad:	76 29                	jbe    140006ad8 <__gdtoa+0x85e>
   140006aaf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ab4:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ab8:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006abc:	7a 0e                	jp     140006acc <__gdtoa+0x852>
   140006abe:	66 0f ef c9          	pxor   xmm1,xmm1
   140006ac2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006ac6:	0f 84 93 0c 00 00    	je     14000775f <__gdtoa+0x14e5>
   140006acc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006ad3:	e9 87 0c 00 00       	jmp    14000775f <__gdtoa+0x14e5>
   140006ad8:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006add:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006ae2:	66 0f 28 c8          	movapd xmm1,xmm0
   140006ae6:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006aea:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006aef:	66 0f 2f c1          	comisd xmm0,xmm1
   140006af3:	0f 87 c3 02 00 00    	ja     140006dbc <__gdtoa+0xb42>
   140006af9:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006afc:	83 c0 01             	add    eax,0x1
   140006aff:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006b02:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006b05:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006b08:	0f 8e 46 01 00 00    	jle    140006c54 <__gdtoa+0x9da>
   140006b0e:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b13:	f2 0f 10 05 7d 48 00 	movsd  xmm0,QWORD PTR [rip+0x487d]        # 14000b398 <.rdata+0x48>
   140006b1a:	00 
   140006b1b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b1f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b24:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b29:	f2 0f 10 05 67 48 00 	movsd  xmm0,QWORD PTR [rip+0x4867]        # 14000b398 <.rdata+0x48>
   140006b30:	00 
   140006b31:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b35:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b3a:	e9 1d ff ff ff       	jmp    140006a5c <__gdtoa+0x7e2>
   140006b3f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b44:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b47:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b4a:	48 8b 05 2f 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b2f]        # 14000b680 <.refptr.__tens_D2A>
   140006b51:	48 63 d2             	movsxd rdx,edx
   140006b54:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006b59:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b5d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b62:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006b69:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b6e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b73:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b77:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b7a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006b7e:	74 1c                	je     140006b9c <__gdtoa+0x922>
   140006b80:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b85:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b89:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b8e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b93:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b97:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b9c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b9f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006ba2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ba6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006baa:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006bae:	89 ca                	mov    edx,ecx
   140006bb0:	88 10                	mov    BYTE PTR [rax],dl
   140006bb2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006bb5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006bb8:	75 73                	jne    140006c2d <__gdtoa+0x9b3>
   140006bba:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006bbf:	f2 0f 10 05 f9 47 00 	movsd  xmm0,QWORD PTR [rip+0x47f9]        # 14000b3c0 <.rdata+0x70>
   140006bc6:	00 
   140006bc7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006bcb:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006bd0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bd5:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006bda:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006bdf:	66 0f 2f c1          	comisd xmm0,xmm1
   140006be3:	0f 87 d6 01 00 00    	ja     140006dbf <__gdtoa+0xb45>
   140006be9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006bee:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006bf3:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006bf8:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006bfc:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c00:	77 02                	ja     140006c04 <__gdtoa+0x98a>
   140006c02:	eb 51                	jmp    140006c55 <__gdtoa+0x9db>
   140006c04:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c09:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c0d:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c11:	7a 0e                	jp     140006c21 <__gdtoa+0x9a7>
   140006c13:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c17:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006c1b:	0f 84 41 0b 00 00    	je     140007762 <__gdtoa+0x14e8>
   140006c21:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006c28:	e9 35 0b 00 00       	jmp    140007762 <__gdtoa+0x14e8>
   140006c2d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c30:	83 c0 01             	add    eax,0x1
   140006c33:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006c36:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c3b:	f2 0f 10 05 55 47 00 	movsd  xmm0,QWORD PTR [rip+0x4755]        # 14000b398 <.rdata+0x48>
   140006c42:	00 
   140006c43:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c47:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c4c:	e9 18 ff ff ff       	jmp    140006b69 <__gdtoa+0x8ef>
   140006c51:	90                   	nop
   140006c52:	eb 01                	jmp    140006c55 <__gdtoa+0x9db>
   140006c54:	90                   	nop
   140006c55:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006c59:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006c5d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006c62:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c67:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006c6a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006c6d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006c70:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006c73:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006c7a:	0f 88 bf 01 00 00    	js     140006e3f <__gdtoa+0xbc5>
   140006c80:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006c87:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006c8a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006c8d:	0f 8f ac 01 00 00    	jg     140006e3f <__gdtoa+0xbc5>
   140006c93:	48 8b 05 e6 49 00 00 	mov    rax,QWORD PTR [rip+0x49e6]        # 14000b680 <.refptr.__tens_D2A>
   140006c9a:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006c9d:	48 63 d2             	movsxd rdx,edx
   140006ca0:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006ca5:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006caa:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006cb1:	79 45                	jns    140006cf8 <__gdtoa+0xa7e>
   140006cb3:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006cb7:	7f 3f                	jg     140006cf8 <__gdtoa+0xa7e>
   140006cb9:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006cc0:	00 
   140006cc1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006cc5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006cc9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ccd:	0f 88 ac 04 00 00    	js     14000717f <__gdtoa+0xf05>
   140006cd3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cd8:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006cdd:	f2 0f 10 05 c3 46 00 	movsd  xmm0,QWORD PTR [rip+0x46c3]        # 14000b3a8 <.rdata+0x58>
   140006ce4:	00 
   140006ce5:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006ce9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006ced:	0f 83 8c 04 00 00    	jae    14000717f <__gdtoa+0xf05>
   140006cf3:	e9 a6 04 00 00       	jmp    14000719e <__gdtoa+0xf24>
   140006cf8:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006cff:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d04:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006d09:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006d0d:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006d10:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d15:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d19:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006d1e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006d23:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006d27:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d2c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006d2f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006d32:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006d36:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006d3a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006d3e:	89 ca                	mov    edx,ecx
   140006d40:	88 10                	mov    BYTE PTR [rax],dl
   140006d42:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d47:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d4b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d4f:	7a 0e                	jp     140006d5f <__gdtoa+0xae5>
   140006d51:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d55:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d59:	0f 84 da 00 00 00    	je     140006e39 <__gdtoa+0xbbf>
   140006d5f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d62:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006d65:	0f 85 aa 00 00 00    	jne    140006e15 <__gdtoa+0xb9b>
   140006d6b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006d6f:	74 12                	je     140006d83 <__gdtoa+0xb09>
   140006d71:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006d75:	74 4b                	je     140006dc2 <__gdtoa+0xb48>
   140006d77:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006d7e:	e9 e3 09 00 00       	jmp    140007766 <__gdtoa+0x14ec>
   140006d83:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d88:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006d8c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d91:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d96:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006d9b:	77 28                	ja     140006dc5 <__gdtoa+0xb4b>
   140006d9d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006da2:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006da7:	7a 63                	jp     140006e0c <__gdtoa+0xb92>
   140006da9:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006dae:	75 5c                	jne    140006e0c <__gdtoa+0xb92>
   140006db0:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006db3:	83 e0 01             	and    eax,0x1
   140006db6:	85 c0                	test   eax,eax
   140006db8:	74 52                	je     140006e0c <__gdtoa+0xb92>
   140006dba:	eb 0a                	jmp    140006dc6 <__gdtoa+0xb4c>
   140006dbc:	90                   	nop
   140006dbd:	eb 07                	jmp    140006dc6 <__gdtoa+0xb4c>
   140006dbf:	90                   	nop
   140006dc0:	eb 04                	jmp    140006dc6 <__gdtoa+0xb4c>
   140006dc2:	90                   	nop
   140006dc3:	eb 01                	jmp    140006dc6 <__gdtoa+0xb4c>
   140006dc5:	90                   	nop
   140006dc6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006dcd:	eb 17                	jmp    140006de6 <__gdtoa+0xb6c>
   140006dcf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006dd3:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006dd7:	75 0d                	jne    140006de6 <__gdtoa+0xb6c>
   140006dd9:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006ddd:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006de1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006de4:	eb 10                	jmp    140006df6 <__gdtoa+0xb7c>
   140006de6:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006deb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006def:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006df2:	3c 39                	cmp    al,0x39
   140006df4:	74 d9                	je     140006dcf <__gdtoa+0xb55>
   140006df6:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006dfa:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006dfe:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e02:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006e05:	83 c2 01             	add    edx,0x1
   140006e08:	88 10                	mov    BYTE PTR [rax],dl
   140006e0a:	eb 2e                	jmp    140006e3a <__gdtoa+0xbc0>
   140006e0c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e13:	eb 25                	jmp    140006e3a <__gdtoa+0xbc0>
   140006e15:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e18:	83 c0 01             	add    eax,0x1
   140006e1b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006e1e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006e23:	f2 0f 10 05 6d 45 00 	movsd  xmm0,QWORD PTR [rip+0x456d]        # 14000b398 <.rdata+0x48>
   140006e2a:	00 
   140006e2b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006e2f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e34:	e9 c6 fe ff ff       	jmp    140006cff <__gdtoa+0xa85>
   140006e39:	90                   	nop
   140006e3a:	e9 27 09 00 00       	jmp    140007766 <__gdtoa+0x14ec>
   140006e3f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006e42:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006e45:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006e48:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006e4b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006e52:	00 
   140006e53:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006e57:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006e5b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006e5f:	0f 84 e0 00 00 00    	je     140006f45 <__gdtoa+0xccb>
   140006e65:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006e68:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006e6b:	29 c2                	sub    edx,eax
   140006e6d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006e70:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e73:	8d 50 01             	lea    edx,[rax+0x1]
   140006e76:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006e79:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006e7f:	29 c2                	sub    edx,eax
   140006e81:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006e88:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006e8b:	39 c2                	cmp    edx,eax
   140006e8d:	7d 43                	jge    140006ed2 <__gdtoa+0xc58>
   140006e8f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006e96:	74 3a                	je     140006ed2 <__gdtoa+0xc58>
   140006e98:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006e9f:	74 31                	je     140006ed2 <__gdtoa+0xc58>
   140006ea1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006ea8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006eab:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006eb1:	29 c2                	sub    edx,eax
   140006eb3:	8d 42 01             	lea    eax,[rdx+0x1]
   140006eb6:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006eb9:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006ec0:	7e 68                	jle    140006f2a <__gdtoa+0xcb0>
   140006ec2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ec6:	7e 62                	jle    140006f2a <__gdtoa+0xcb0>
   140006ec8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006ecb:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006ece:	7d 5a                	jge    140006f2a <__gdtoa+0xcb0>
   140006ed0:	eb 0a                	jmp    140006edc <__gdtoa+0xc62>
   140006ed2:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006ed9:	7e 50                	jle    140006f2b <__gdtoa+0xcb1>
   140006edb:	90                   	nop
   140006edc:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006edf:	83 e8 01             	sub    eax,0x1
   140006ee2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006ee5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006ee8:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006eeb:	7c 08                	jl     140006ef5 <__gdtoa+0xc7b>
   140006eed:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006ef0:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140006ef3:	eb 19                	jmp    140006f0e <__gdtoa+0xc94>
   140006ef5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006ef8:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   140006efb:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006efe:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140006f01:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006f04:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140006f07:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   140006f0e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006f11:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f14:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f17:	85 c0                	test   eax,eax
   140006f19:	79 10                	jns    140006f2b <__gdtoa+0xcb1>
   140006f1b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f1e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f21:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006f28:	eb 01                	jmp    140006f2b <__gdtoa+0xcb1>
   140006f2a:	90                   	nop
   140006f2b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f2e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140006f31:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f34:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140006f37:	b9 01 00 00 00       	mov    ecx,0x1
   140006f3c:	e8 f6 0f 00 00       	call   140007f37 <__i2b_D2A>
   140006f41:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f45:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140006f49:	7e 26                	jle    140006f71 <__gdtoa+0xcf7>
   140006f4b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   140006f4f:	7e 20                	jle    140006f71 <__gdtoa+0xcf7>
   140006f51:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140006f54:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140006f57:	39 c2                	cmp    edx,eax
   140006f59:	0f 4e c2             	cmovle eax,edx
   140006f5c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f5f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f62:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140006f65:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f68:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140006f6b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f6e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140006f71:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140006f75:	7e 7e                	jle    140006ff5 <__gdtoa+0xd7b>
   140006f77:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f7b:	74 65                	je     140006fe2 <__gdtoa+0xd68>
   140006f7d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140006f81:	7e 3b                	jle    140006fbe <__gdtoa+0xd44>
   140006f83:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140006f86:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006f8a:	48 89 c1             	mov    rcx,rax
   140006f8d:	e8 11 12 00 00       	call   1400081a3 <__pow5mult_D2A>
   140006f92:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f96:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140006f9a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006f9e:	48 89 c1             	mov    rcx,rax
   140006fa1:	e8 d7 0f 00 00       	call   140007f7d <__mult_D2A>
   140006fa6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140006faa:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fae:	48 89 c1             	mov    rcx,rax
   140006fb1:	e8 c8 0d 00 00       	call   140007d7e <__Bfree_D2A>
   140006fb6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006fba:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006fbe:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006fc1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   140006fc4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006fc7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006fcb:	74 28                	je     140006ff5 <__gdtoa+0xd7b>
   140006fcd:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   140006fd0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fd4:	48 89 c1             	mov    rcx,rax
   140006fd7:	e8 c7 11 00 00       	call   1400081a3 <__pow5mult_D2A>
   140006fdc:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006fe0:	eb 13                	jmp    140006ff5 <__gdtoa+0xd7b>
   140006fe2:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   140006fe5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006fe9:	48 89 c1             	mov    rcx,rax
   140006fec:	e8 b2 11 00 00       	call   1400081a3 <__pow5mult_D2A>
   140006ff1:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140006ff5:	b9 01 00 00 00       	mov    ecx,0x1
   140006ffa:	e8 38 0f 00 00       	call   140007f37 <__i2b_D2A>
   140006fff:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007003:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007007:	7e 13                	jle    14000701c <__gdtoa+0xda2>
   140007009:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   14000700c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007010:	48 89 c1             	mov    rcx,rax
   140007013:	e8 8b 11 00 00       	call   1400081a3 <__pow5mult_D2A>
   140007018:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000701c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007023:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000702a:	7f 29                	jg     140007055 <__gdtoa+0xddb>
   14000702c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000702f:	83 f8 01             	cmp    eax,0x1
   140007032:	75 21                	jne    140007055 <__gdtoa+0xddb>
   140007034:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000703b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000703e:	83 c0 01             	add    eax,0x1
   140007041:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007044:	7e 0f                	jle    140007055 <__gdtoa+0xddb>
   140007046:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000704a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000704e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007055:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007059:	74 22                	je     14000707d <__gdtoa+0xe03>
   14000705b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000705f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007062:	8d 50 ff             	lea    edx,[rax-0x1]
   140007065:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007069:	48 63 d2             	movsxd rdx,edx
   14000706c:	48 83 c2 04          	add    rdx,0x4
   140007070:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007074:	89 c1                	mov    ecx,eax
   140007076:	e8 c5 f0 ff ff       	call   140006140 <__hi0bits_D2A>
   14000707b:	eb 05                	jmp    140007082 <__gdtoa+0xe08>
   14000707d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007082:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007085:	83 e8 04             	sub    eax,0x4
   140007088:	83 e0 1f             	and    eax,0x1f
   14000708b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000708e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007091:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   140007094:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007097:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   14000709a:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   14000709e:	7e 13                	jle    1400070b3 <__gdtoa+0xe39>
   1400070a0:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   1400070a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070a7:	48 89 c1             	mov    rcx,rax
   1400070aa:	e8 b1 12 00 00       	call   140008360 <__lshift_D2A>
   1400070af:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070b3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400070b6:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400070b9:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   1400070bd:	7e 13                	jle    1400070d2 <__gdtoa+0xe58>
   1400070bf:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400070c2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400070c6:	48 89 c1             	mov    rcx,rax
   1400070c9:	e8 92 12 00 00       	call   140008360 <__lshift_D2A>
   1400070ce:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400070d2:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400070d6:	74 5a                	je     140007132 <__gdtoa+0xeb8>
   1400070d8:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400070dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070e0:	48 89 c1             	mov    rcx,rax
   1400070e3:	e8 05 14 00 00       	call   1400084ed <__cmp_D2A>
   1400070e8:	85 c0                	test   eax,eax
   1400070ea:	79 46                	jns    140007132 <__gdtoa+0xeb8>
   1400070ec:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   1400070f0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070f4:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400070fa:	ba 0a 00 00 00       	mov    edx,0xa
   1400070ff:	48 89 c1             	mov    rcx,rax
   140007102:	e8 02 0d 00 00       	call   140007e09 <__multadd_D2A>
   140007107:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000710b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000710f:	74 1b                	je     14000712c <__gdtoa+0xeb2>
   140007111:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007115:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000711b:	ba 0a 00 00 00       	mov    edx,0xa
   140007120:	48 89 c1             	mov    rcx,rax
   140007123:	e8 e1 0c 00 00       	call   140007e09 <__multadd_D2A>
   140007128:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000712c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000712f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007132:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007136:	0f 8f 81 00 00 00    	jg     1400071bd <__gdtoa+0xf43>
   14000713c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007143:	7e 78                	jle    1400071bd <__gdtoa+0xf43>
   140007145:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007149:	78 37                	js     140007182 <__gdtoa+0xf08>
   14000714b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000714f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007155:	ba 05 00 00 00       	mov    edx,0x5
   14000715a:	48 89 c1             	mov    rcx,rax
   14000715d:	e8 a7 0c 00 00       	call   140007e09 <__multadd_D2A>
   140007162:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007166:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000716a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000716e:	48 89 c1             	mov    rcx,rax
   140007171:	e8 77 13 00 00       	call   1400084ed <__cmp_D2A>
   140007176:	85 c0                	test   eax,eax
   140007178:	7f 23                	jg     14000719d <__gdtoa+0xf23>
   14000717a:	eb 07                	jmp    140007183 <__gdtoa+0xf09>
   14000717c:	90                   	nop
   14000717d:	eb 04                	jmp    140007183 <__gdtoa+0xf09>
   14000717f:	90                   	nop
   140007180:	eb 01                	jmp    140007183 <__gdtoa+0xf09>
   140007182:	90                   	nop
   140007183:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007189:	f7 d0                	not    eax
   14000718b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000718e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007195:	e9 87 05 00 00       	jmp    140007721 <__gdtoa+0x14a7>
   14000719a:	90                   	nop
   14000719b:	eb 01                	jmp    14000719e <__gdtoa+0xf24>
   14000719d:	90                   	nop
   14000719e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400071a5:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400071a9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400071ad:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400071b1:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400071b4:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400071b8:	e9 64 05 00 00       	jmp    140007721 <__gdtoa+0x14a7>
   1400071bd:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400071c1:	0f 84 14 04 00 00    	je     1400075db <__gdtoa+0x1361>
   1400071c7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400071cb:	7e 13                	jle    1400071e0 <__gdtoa+0xf66>
   1400071cd:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   1400071d0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071d4:	48 89 c1             	mov    rcx,rax
   1400071d7:	e8 84 11 00 00       	call   140008360 <__lshift_D2A>
   1400071dc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400071e0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071e4:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400071e8:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   1400071ec:	74 57                	je     140007245 <__gdtoa+0xfcb>
   1400071ee:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400071f2:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400071f5:	89 c1                	mov    ecx,eax
   1400071f7:	e8 41 0a 00 00       	call   140007c3d <__Balloc_D2A>
   1400071fc:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007200:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007204:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007207:	48 98                	cdqe
   140007209:	48 83 c0 02          	add    rax,0x2
   14000720d:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007214:	00 
   140007215:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007219:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000721d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007221:	48 83 c0 10          	add    rax,0x10
   140007225:	49 89 c8             	mov    r8,rcx
   140007228:	48 89 c1             	mov    rcx,rax
   14000722b:	e8 f0 23 00 00       	call   140009620 <memcpy>
   140007230:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007234:	ba 01 00 00 00       	mov    edx,0x1
   140007239:	48 89 c1             	mov    rcx,rax
   14000723c:	e8 1f 11 00 00       	call   140008360 <__lshift_D2A>
   140007241:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007245:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000724c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007250:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007254:	48 89 c1             	mov    rcx,rax
   140007257:	e8 62 ec ff ff       	call   140005ebe <__quorem_D2A>
   14000725c:	83 c0 30             	add    eax,0x30
   14000725f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007262:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007266:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000726a:	48 89 c1             	mov    rcx,rax
   14000726d:	e8 7b 12 00 00       	call   1400084ed <__cmp_D2A>
   140007272:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007275:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007279:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000727d:	48 89 c1             	mov    rcx,rax
   140007280:	e8 38 13 00 00       	call   1400085bd <__diff_D2A>
   140007285:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007289:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000728d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140007290:	85 c0                	test   eax,eax
   140007292:	75 15                	jne    1400072a9 <__gdtoa+0x102f>
   140007294:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140007298:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000729c:	48 89 c1             	mov    rcx,rax
   14000729f:	e8 49 12 00 00       	call   1400084ed <__cmp_D2A>
   1400072a4:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400072a7:	eb 07                	jmp    1400072b0 <__gdtoa+0x1036>
   1400072a9:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   1400072b0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400072b4:	48 89 c1             	mov    rcx,rax
   1400072b7:	e8 c2 0a 00 00       	call   140007d7e <__Bfree_D2A>
   1400072bc:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400072c0:	75 70                	jne    140007332 <__gdtoa+0x10b8>
   1400072c2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400072c9:	75 67                	jne    140007332 <__gdtoa+0x10b8>
   1400072cb:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400072d2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400072d4:	83 e0 01             	and    eax,0x1
   1400072d7:	85 c0                	test   eax,eax
   1400072d9:	75 57                	jne    140007332 <__gdtoa+0x10b8>
   1400072db:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400072df:	75 51                	jne    140007332 <__gdtoa+0x10b8>
   1400072e1:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400072e5:	0f 84 01 02 00 00    	je     1400074ec <__gdtoa+0x1272>
   1400072eb:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400072ef:	7f 20                	jg     140007311 <__gdtoa+0x1097>
   1400072f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400072f5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400072f8:	83 f8 01             	cmp    eax,0x1
   1400072fb:	7f 0b                	jg     140007308 <__gdtoa+0x108e>
   1400072fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007301:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007304:	85 c0                	test   eax,eax
   140007306:	74 14                	je     14000731c <__gdtoa+0x10a2>
   140007308:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000730f:	eb 0b                	jmp    14000731c <__gdtoa+0x10a2>
   140007311:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007315:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000731c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007320:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007324:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007328:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000732b:	88 10                	mov    BYTE PTR [rax],dl
   14000732d:	e9 ef 03 00 00       	jmp    140007721 <__gdtoa+0x14a7>
   140007332:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007336:	78 2b                	js     140007363 <__gdtoa+0x10e9>
   140007338:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000733c:	0f 85 96 01 00 00    	jne    1400074d8 <__gdtoa+0x125e>
   140007342:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007349:	0f 85 89 01 00 00    	jne    1400074d8 <__gdtoa+0x125e>
   14000734f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007356:	8b 00                	mov    eax,DWORD PTR [rax]
   140007358:	83 e0 01             	and    eax,0x1
   14000735b:	85 c0                	test   eax,eax
   14000735d:	0f 85 75 01 00 00    	jne    1400074d8 <__gdtoa+0x125e>
   140007363:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007367:	0f 84 db 00 00 00    	je     140007448 <__gdtoa+0x11ce>
   14000736d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007371:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007374:	83 f8 01             	cmp    eax,0x1
   140007377:	7f 0f                	jg     140007388 <__gdtoa+0x110e>
   140007379:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000737d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007380:	85 c0                	test   eax,eax
   140007382:	0f 84 c0 00 00 00    	je     140007448 <__gdtoa+0x11ce>
   140007388:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000738c:	0f 85 83 00 00 00    	jne    140007415 <__gdtoa+0x119b>
   140007392:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140007399:	e9 24 01 00 00       	jmp    1400074c2 <__gdtoa+0x1248>
   14000739e:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400073a2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400073a6:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400073aa:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400073ad:	88 10                	mov    BYTE PTR [rax],dl
   1400073af:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400073b3:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400073b9:	ba 0a 00 00 00       	mov    edx,0xa
   1400073be:	48 89 c1             	mov    rcx,rax
   1400073c1:	e8 43 0a 00 00       	call   140007e09 <__multadd_D2A>
   1400073c6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400073ca:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400073ce:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400073d2:	75 08                	jne    1400073dc <__gdtoa+0x1162>
   1400073d4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400073d8:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400073dc:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400073e0:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400073e4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073e8:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400073ee:	ba 0a 00 00 00       	mov    edx,0xa
   1400073f3:	48 89 c1             	mov    rcx,rax
   1400073f6:	e8 0e 0a 00 00       	call   140007e09 <__multadd_D2A>
   1400073fb:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400073ff:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007403:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007407:	48 89 c1             	mov    rcx,rax
   14000740a:	e8 af ea ff ff       	call   140005ebe <__quorem_D2A>
   14000740f:	83 c0 30             	add    eax,0x30
   140007412:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007415:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007419:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000741d:	48 89 c1             	mov    rcx,rax
   140007420:	e8 c8 10 00 00       	call   1400084ed <__cmp_D2A>
   140007425:	85 c0                	test   eax,eax
   140007427:	0f 8f 71 ff ff ff    	jg     14000739e <__gdtoa+0x1124>
   14000742d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007430:	8d 50 01             	lea    edx,[rax+0x1]
   140007433:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007436:	83 f8 39             	cmp    eax,0x39
   140007439:	0f 84 b0 00 00 00    	je     1400074ef <__gdtoa+0x1275>
   14000743f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007446:	eb 7a                	jmp    1400074c2 <__gdtoa+0x1248>
   140007448:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000744c:	7e 53                	jle    1400074a1 <__gdtoa+0x1227>
   14000744e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007452:	ba 01 00 00 00       	mov    edx,0x1
   140007457:	48 89 c1             	mov    rcx,rax
   14000745a:	e8 01 0f 00 00       	call   140008360 <__lshift_D2A>
   14000745f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007463:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007467:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000746b:	48 89 c1             	mov    rcx,rax
   14000746e:	e8 7a 10 00 00       	call   1400084ed <__cmp_D2A>
   140007473:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007476:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000747a:	7f 10                	jg     14000748c <__gdtoa+0x1212>
   14000747c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007480:	75 18                	jne    14000749a <__gdtoa+0x1220>
   140007482:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007485:	83 e0 01             	and    eax,0x1
   140007488:	85 c0                	test   eax,eax
   14000748a:	74 0e                	je     14000749a <__gdtoa+0x1220>
   14000748c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000748f:	8d 50 01             	lea    edx,[rax+0x1]
   140007492:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007495:	83 f8 39             	cmp    eax,0x39
   140007498:	74 58                	je     1400074f2 <__gdtoa+0x1278>
   14000749a:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400074a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074a5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400074a8:	83 f8 01             	cmp    eax,0x1
   1400074ab:	7f 0b                	jg     1400074b8 <__gdtoa+0x123e>
   1400074ad:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074b1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400074b4:	85 c0                	test   eax,eax
   1400074b6:	74 09                	je     1400074c1 <__gdtoa+0x1247>
   1400074b8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400074bf:	eb 01                	jmp    1400074c2 <__gdtoa+0x1248>
   1400074c1:	90                   	nop
   1400074c2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074c6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074ca:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074ce:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400074d1:	88 10                	mov    BYTE PTR [rax],dl
   1400074d3:	e9 49 02 00 00       	jmp    140007721 <__gdtoa+0x14a7>
   1400074d8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400074dc:	7e 52                	jle    140007530 <__gdtoa+0x12b6>
   1400074de:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400074e2:	74 4c                	je     140007530 <__gdtoa+0x12b6>
   1400074e4:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400074e8:	75 24                	jne    14000750e <__gdtoa+0x1294>
   1400074ea:	eb 07                	jmp    1400074f3 <__gdtoa+0x1279>
   1400074ec:	90                   	nop
   1400074ed:	eb 04                	jmp    1400074f3 <__gdtoa+0x1279>
   1400074ef:	90                   	nop
   1400074f0:	eb 01                	jmp    1400074f3 <__gdtoa+0x1279>
   1400074f2:	90                   	nop
   1400074f3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074f7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074fb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074ff:	c6 00 39             	mov    BYTE PTR [rax],0x39
   140007502:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007509:	e9 9d 01 00 00       	jmp    1400076ab <__gdtoa+0x1431>
   14000750e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007515:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007518:	8d 48 01             	lea    ecx,[rax+0x1]
   14000751b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000751f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007523:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007527:	89 ca                	mov    edx,ecx
   140007529:	88 10                	mov    BYTE PTR [rax],dl
   14000752b:	e9 f1 01 00 00       	jmp    140007721 <__gdtoa+0x14a7>
   140007530:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007534:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007538:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000753c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000753f:	88 10                	mov    BYTE PTR [rax],dl
   140007541:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007544:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007547:	0f 84 ea 00 00 00    	je     140007637 <__gdtoa+0x13bd>
   14000754d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007551:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007557:	ba 0a 00 00 00       	mov    edx,0xa
   14000755c:	48 89 c1             	mov    rcx,rax
   14000755f:	e8 a5 08 00 00       	call   140007e09 <__multadd_D2A>
   140007564:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007568:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000756c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007570:	75 25                	jne    140007597 <__gdtoa+0x131d>
   140007572:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007576:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000757c:	ba 0a 00 00 00       	mov    edx,0xa
   140007581:	48 89 c1             	mov    rcx,rax
   140007584:	e8 80 08 00 00       	call   140007e09 <__multadd_D2A>
   140007589:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000758d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007591:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   140007595:	eb 36                	jmp    1400075cd <__gdtoa+0x1353>
   140007597:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000759b:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075a1:	ba 0a 00 00 00       	mov    edx,0xa
   1400075a6:	48 89 c1             	mov    rcx,rax
   1400075a9:	e8 5b 08 00 00       	call   140007e09 <__multadd_D2A>
   1400075ae:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400075b2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400075b6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400075bc:	ba 0a 00 00 00       	mov    edx,0xa
   1400075c1:	48 89 c1             	mov    rcx,rax
   1400075c4:	e8 40 08 00 00       	call   140007e09 <__multadd_D2A>
   1400075c9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400075cd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400075d0:	83 c0 01             	add    eax,0x1
   1400075d3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400075d6:	e9 71 fc ff ff       	jmp    14000724c <__gdtoa+0xfd2>
   1400075db:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400075e2:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400075e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075ea:	48 89 c1             	mov    rcx,rax
   1400075ed:	e8 cc e8 ff ff       	call   140005ebe <__quorem_D2A>
   1400075f2:	83 c0 30             	add    eax,0x30
   1400075f5:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   1400075f8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075fc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007600:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007604:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007607:	88 10                	mov    BYTE PTR [rax],dl
   140007609:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000760c:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   14000760f:	7e 29                	jle    14000763a <__gdtoa+0x13c0>
   140007611:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007615:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000761b:	ba 0a 00 00 00       	mov    edx,0xa
   140007620:	48 89 c1             	mov    rcx,rax
   140007623:	e8 e1 07 00 00       	call   140007e09 <__multadd_D2A>
   140007628:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000762c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000762f:	83 c0 01             	add    eax,0x1
   140007632:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007635:	eb ab                	jmp    1400075e2 <__gdtoa+0x1368>
   140007637:	90                   	nop
   140007638:	eb 01                	jmp    14000763b <__gdtoa+0x13c1>
   14000763a:	90                   	nop
   14000763b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000763f:	74 26                	je     140007667 <__gdtoa+0x13ed>
   140007641:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007645:	0f 84 ae 00 00 00    	je     1400076f9 <__gdtoa+0x147f>
   14000764b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000764f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007652:	83 f8 01             	cmp    eax,0x1
   140007655:	7f 50                	jg     1400076a7 <__gdtoa+0x142d>
   140007657:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000765b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000765e:	85 c0                	test   eax,eax
   140007660:	75 45                	jne    1400076a7 <__gdtoa+0x142d>
   140007662:	e9 92 00 00 00       	jmp    1400076f9 <__gdtoa+0x147f>
   140007667:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000766b:	ba 01 00 00 00       	mov    edx,0x1
   140007670:	48 89 c1             	mov    rcx,rax
   140007673:	e8 e8 0c 00 00       	call   140008360 <__lshift_D2A>
   140007678:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000767c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007680:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007684:	48 89 c1             	mov    rcx,rax
   140007687:	e8 61 0e 00 00       	call   1400084ed <__cmp_D2A>
   14000768c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000768f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007693:	7f 15                	jg     1400076aa <__gdtoa+0x1430>
   140007695:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007699:	75 61                	jne    1400076fc <__gdtoa+0x1482>
   14000769b:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000769e:	83 e0 01             	and    eax,0x1
   1400076a1:	85 c0                	test   eax,eax
   1400076a3:	74 5a                	je     1400076ff <__gdtoa+0x1485>
   1400076a5:	eb 04                	jmp    1400076ab <__gdtoa+0x1431>
   1400076a7:	90                   	nop
   1400076a8:	eb 01                	jmp    1400076ab <__gdtoa+0x1431>
   1400076aa:	90                   	nop
   1400076ab:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400076b2:	eb 1f                	jmp    1400076d3 <__gdtoa+0x1459>
   1400076b4:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076b8:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400076bc:	75 15                	jne    1400076d3 <__gdtoa+0x1459>
   1400076be:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400076c2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076c6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076ca:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076ce:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400076d1:	eb 4e                	jmp    140007721 <__gdtoa+0x14a7>
   1400076d3:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400076d8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076dc:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400076df:	3c 39                	cmp    al,0x39
   1400076e1:	74 d1                	je     1400076b4 <__gdtoa+0x143a>
   1400076e3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400076e7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400076eb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400076ef:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   1400076f2:	83 c2 01             	add    edx,0x1
   1400076f5:	88 10                	mov    BYTE PTR [rax],dl
   1400076f7:	eb 28                	jmp    140007721 <__gdtoa+0x14a7>
   1400076f9:	90                   	nop
   1400076fa:	eb 04                	jmp    140007700 <__gdtoa+0x1486>
   1400076fc:	90                   	nop
   1400076fd:	eb 01                	jmp    140007700 <__gdtoa+0x1486>
   1400076ff:	90                   	nop
   140007700:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007704:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007707:	83 f8 01             	cmp    eax,0x1
   14000770a:	7f 0b                	jg     140007717 <__gdtoa+0x149d>
   14000770c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007710:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007713:	85 c0                	test   eax,eax
   140007715:	74 09                	je     140007720 <__gdtoa+0x14a6>
   140007717:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000771e:	eb 01                	jmp    140007721 <__gdtoa+0x14a7>
   140007720:	90                   	nop
   140007721:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007725:	48 89 c1             	mov    rcx,rax
   140007728:	e8 51 06 00 00       	call   140007d7e <__Bfree_D2A>
   14000772d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007732:	74 31                	je     140007765 <__gdtoa+0x14eb>
   140007734:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007739:	74 16                	je     140007751 <__gdtoa+0x14d7>
   14000773b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000773f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007743:	74 0c                	je     140007751 <__gdtoa+0x14d7>
   140007745:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007749:	48 89 c1             	mov    rcx,rax
   14000774c:	e8 2d 06 00 00       	call   140007d7e <__Bfree_D2A>
   140007751:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007755:	48 89 c1             	mov    rcx,rax
   140007758:	e8 21 06 00 00       	call   140007d7e <__Bfree_D2A>
   14000775d:	eb 0e                	jmp    14000776d <__gdtoa+0x14f3>
   14000775f:	90                   	nop
   140007760:	eb 0b                	jmp    14000776d <__gdtoa+0x14f3>
   140007762:	90                   	nop
   140007763:	eb 08                	jmp    14000776d <__gdtoa+0x14f3>
   140007765:	90                   	nop
   140007766:	eb 05                	jmp    14000776d <__gdtoa+0x14f3>
   140007768:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000776d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007771:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007775:	73 0f                	jae    140007786 <__gdtoa+0x150c>
   140007777:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000777b:	48 83 e8 01          	sub    rax,0x1
   14000777f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007782:	3c 30                	cmp    al,0x30
   140007784:	74 e2                	je     140007768 <__gdtoa+0x14ee>
   140007786:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000778a:	48 89 c1             	mov    rcx,rax
   14000778d:	e8 ec 05 00 00       	call   140007d7e <__Bfree_D2A>
   140007792:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007796:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140007799:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000779c:	8d 50 01             	lea    edx,[rax+0x1]
   14000779f:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400077a6:	89 10                	mov    DWORD PTR [rax],edx
   1400077a8:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   1400077af:	00 
   1400077b0:	74 0e                	je     1400077c0 <__gdtoa+0x1546>
   1400077b2:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400077b9:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   1400077bd:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400077c0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400077c7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400077c9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400077cc:	89 c2                	mov    edx,eax
   1400077ce:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400077d5:	89 10                	mov    DWORD PTR [rax],edx
   1400077d7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400077db:	48 81 c4 00 01 00 00 	add    rsp,0x100
   1400077e2:	5d                   	pop    rbp
   1400077e3:	c3                   	ret
   1400077e4:	90                   	nop
   1400077e5:	90                   	nop
   1400077e6:	90                   	nop
   1400077e7:	90                   	nop
   1400077e8:	90                   	nop
   1400077e9:	90                   	nop
   1400077ea:	90                   	nop
   1400077eb:	90                   	nop
   1400077ec:	90                   	nop
   1400077ed:	90                   	nop
   1400077ee:	90                   	nop
   1400077ef:	90                   	nop

00000001400077f0 <__lo0bits_D2A>:
   1400077f0:	55                   	push   rbp
   1400077f1:	48 89 e5             	mov    rbp,rsp
   1400077f4:	48 83 ec 10          	sub    rsp,0x10
   1400077f8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400077fc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007800:	8b 00                	mov    eax,DWORD PTR [rax]
   140007802:	f3 0f bc c0          	tzcnt  eax,eax
   140007806:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007809:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000780d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000780f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007812:	89 c1                	mov    ecx,eax
   140007814:	d3 ea                	shr    edx,cl
   140007816:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000781a:	89 10                	mov    DWORD PTR [rax],edx
   14000781c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000781f:	48 83 c4 10          	add    rsp,0x10
   140007823:	5d                   	pop    rbp
   140007824:	c3                   	ret

0000000140007825 <__rshift_D2A>:
   140007825:	55                   	push   rbp
   140007826:	48 89 e5             	mov    rbp,rsp
   140007829:	48 83 ec 20          	sub    rsp,0x20
   14000782d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007831:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007834:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007838:	48 83 c0 18          	add    rax,0x18
   14000783c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007840:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007844:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007848:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000784b:	c1 f8 05             	sar    eax,0x5
   14000784e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007851:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007855:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007858:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000785b:	0f 8d e4 00 00 00    	jge    140007945 <__rshift_D2A+0x120>
   140007861:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007865:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007868:	48 98                	cdqe
   14000786a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007871:	00 
   140007872:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007876:	48 01 d0             	add    rax,rdx
   140007879:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000787d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007880:	48 98                	cdqe
   140007882:	48 c1 e0 02          	shl    rax,0x2
   140007886:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000788a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000788e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140007892:	0f 84 a3 00 00 00    	je     14000793b <__rshift_D2A+0x116>
   140007898:	b8 20 00 00 00       	mov    eax,0x20
   14000789d:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400078a0:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400078a3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078a7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078ab:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400078af:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078b1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078b4:	89 c1                	mov    ecx,eax
   1400078b6:	d3 ea                	shr    edx,cl
   1400078b8:	89 d0                	mov    eax,edx
   1400078ba:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400078bd:	eb 3c                	jmp    1400078fb <__rshift_D2A+0xd6>
   1400078bf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078c3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078c5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400078c8:	89 c1                	mov    ecx,eax
   1400078ca:	d3 e2                	shl    edx,cl
   1400078cc:	89 d1                	mov    ecx,edx
   1400078ce:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400078d2:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078d6:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400078da:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   1400078dd:	89 ca                	mov    edx,ecx
   1400078df:	89 10                	mov    DWORD PTR [rax],edx
   1400078e1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078e5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400078e9:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400078ed:	8b 10                	mov    edx,DWORD PTR [rax]
   1400078ef:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400078f2:	89 c1                	mov    ecx,eax
   1400078f4:	d3 ea                	shr    edx,cl
   1400078f6:	89 d0                	mov    eax,edx
   1400078f8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400078fb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400078ff:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007903:	72 ba                	jb     1400078bf <__rshift_D2A+0x9a>
   140007905:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007909:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   14000790c:	89 10                	mov    DWORD PTR [rax],edx
   14000790e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007912:	8b 00                	mov    eax,DWORD PTR [rax]
   140007914:	85 c0                	test   eax,eax
   140007916:	74 2d                	je     140007945 <__rshift_D2A+0x120>
   140007918:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   14000791d:	eb 26                	jmp    140007945 <__rshift_D2A+0x120>
   14000791f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007923:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007927:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000792b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000792f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007933:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007937:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007939:	89 10                	mov    DWORD PTR [rax],edx
   14000793b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000793f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007943:	72 da                	jb     14000791f <__rshift_D2A+0xfa>
   140007945:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007949:	48 83 c0 18          	add    rax,0x18
   14000794d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007951:	48 29 c2             	sub    rdx,rax
   140007954:	48 89 d0             	mov    rax,rdx
   140007957:	48 c1 f8 02          	sar    rax,0x2
   14000795b:	89 c2                	mov    edx,eax
   14000795d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007961:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007964:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007968:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000796b:	85 c0                	test   eax,eax
   14000796d:	75 0b                	jne    14000797a <__rshift_D2A+0x155>
   14000796f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007973:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000797a:	90                   	nop
   14000797b:	48 83 c4 20          	add    rsp,0x20
   14000797f:	5d                   	pop    rbp
   140007980:	c3                   	ret

0000000140007981 <__trailz_D2A>:
   140007981:	55                   	push   rbp
   140007982:	48 89 e5             	mov    rbp,rsp
   140007985:	48 83 ec 40          	sub    rsp,0x40
   140007989:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000798d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007994:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007998:	48 83 c0 18          	add    rax,0x18
   14000799c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400079a0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400079a4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400079a7:	48 98                	cdqe
   1400079a9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400079b0:	00 
   1400079b1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079b5:	48 01 d0             	add    rax,rdx
   1400079b8:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400079bc:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   1400079c3:	eb 09                	jmp    1400079ce <__trailz_D2A+0x4d>
   1400079c5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   1400079c9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   1400079ce:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079d2:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400079d6:	73 0a                	jae    1400079e2 <__trailz_D2A+0x61>
   1400079d8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079dc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079de:	85 c0                	test   eax,eax
   1400079e0:	74 e3                	je     1400079c5 <__trailz_D2A+0x44>
   1400079e2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079e6:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400079ea:	73 18                	jae    140007a04 <__trailz_D2A+0x83>
   1400079ec:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079f0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400079f2:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400079f5:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   1400079f9:	48 89 c1             	mov    rcx,rax
   1400079fc:	e8 ef fd ff ff       	call   1400077f0 <__lo0bits_D2A>
   140007a01:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007a04:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007a07:	48 83 c4 40          	add    rsp,0x40
   140007a0b:	5d                   	pop    rbp
   140007a0c:	c3                   	ret
   140007a0d:	90                   	nop
   140007a0e:	90                   	nop
   140007a0f:	90                   	nop

0000000140007a10 <dtoa_lock_cleanup>:
   140007a10:	55                   	push   rbp
   140007a11:	48 89 e5             	mov    rbp,rsp
   140007a14:	48 83 ec 40          	sub    rsp,0x40
   140007a18:	48 8d 05 d1 77 00 00 	lea    rax,[rip+0x77d1]        # 14000f1f0 <dtoa_CS_init>
   140007a1f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007a23:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007a2a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007a2d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a31:	87 10                	xchg   DWORD PTR [rax],edx
   140007a33:	89 d0                	mov    eax,edx
   140007a35:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007a38:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007a3c:	75 3d                	jne    140007a7b <dtoa_lock_cleanup+0x6b>
   140007a3e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007a45:	eb 2e                	jmp    140007a75 <dtoa_lock_cleanup+0x65>
   140007a47:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007a4a:	48 63 d0             	movsxd rdx,eax
   140007a4d:	48 89 d0             	mov    rax,rdx
   140007a50:	48 c1 e0 02          	shl    rax,0x2
   140007a54:	48 01 d0             	add    rax,rdx
   140007a57:	48 c1 e0 03          	shl    rax,0x3
   140007a5b:	48 8d 15 3e 77 00 00 	lea    rdx,[rip+0x773e]        # 14000f1a0 <dtoa_CritSec>
   140007a62:	48 01 d0             	add    rax,rdx
   140007a65:	48 89 c1             	mov    rcx,rax
   140007a68:	48 8b 05 81 87 00 00 	mov    rax,QWORD PTR [rip+0x8781]        # 1400101f0 <__IAT_start__>
   140007a6f:	ff d0                	call   rax
   140007a71:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007a75:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007a79:	7e cc                	jle    140007a47 <dtoa_lock_cleanup+0x37>
   140007a7b:	90                   	nop
   140007a7c:	48 83 c4 40          	add    rsp,0x40
   140007a80:	5d                   	pop    rbp
   140007a81:	c3                   	ret

0000000140007a82 <dtoa_lock>:
   140007a82:	55                   	push   rbp
   140007a83:	48 89 e5             	mov    rbp,rsp
   140007a86:	48 83 ec 40          	sub    rsp,0x40
   140007a8a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007a8d:	8b 05 5d 77 00 00    	mov    eax,DWORD PTR [rip+0x775d]        # 14000f1f0 <dtoa_CS_init>
   140007a93:	83 f8 02             	cmp    eax,0x2
   140007a96:	75 2c                	jne    140007ac4 <dtoa_lock+0x42>
   140007a98:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007a9b:	48 89 d0             	mov    rax,rdx
   140007a9e:	48 c1 e0 02          	shl    rax,0x2
   140007aa2:	48 01 d0             	add    rax,rdx
   140007aa5:	48 c1 e0 03          	shl    rax,0x3
   140007aa9:	48 8d 15 f0 76 00 00 	lea    rdx,[rip+0x76f0]        # 14000f1a0 <dtoa_CritSec>
   140007ab0:	48 01 d0             	add    rax,rdx
   140007ab3:	48 89 c1             	mov    rcx,rax
   140007ab6:	48 8b 05 3b 87 00 00 	mov    rax,QWORD PTR [rip+0x873b]        # 1400101f8 <__imp_EnterCriticalSection>
   140007abd:	ff d0                	call   rax
   140007abf:	e9 ea 00 00 00       	jmp    140007bae <dtoa_lock+0x12c>
   140007ac4:	8b 05 26 77 00 00    	mov    eax,DWORD PTR [rip+0x7726]        # 14000f1f0 <dtoa_CS_init>
   140007aca:	85 c0                	test   eax,eax
   140007acc:	0f 85 9e 00 00 00    	jne    140007b70 <dtoa_lock+0xee>
   140007ad2:	48 8d 05 17 77 00 00 	lea    rax,[rip+0x7717]        # 14000f1f0 <dtoa_CS_init>
   140007ad9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007add:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007ae4:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007ae7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007aeb:	87 10                	xchg   DWORD PTR [rax],edx
   140007aed:	89 d0                	mov    eax,edx
   140007aef:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007af2:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007af6:	75 58                	jne    140007b50 <dtoa_lock+0xce>
   140007af8:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007aff:	eb 2e                	jmp    140007b2f <dtoa_lock+0xad>
   140007b01:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b04:	48 63 d0             	movsxd rdx,eax
   140007b07:	48 89 d0             	mov    rax,rdx
   140007b0a:	48 c1 e0 02          	shl    rax,0x2
   140007b0e:	48 01 d0             	add    rax,rdx
   140007b11:	48 c1 e0 03          	shl    rax,0x3
   140007b15:	48 8d 15 84 76 00 00 	lea    rdx,[rip+0x7684]        # 14000f1a0 <dtoa_CritSec>
   140007b1c:	48 01 d0             	add    rax,rdx
   140007b1f:	48 89 c1             	mov    rcx,rax
   140007b22:	48 8b 05 ff 86 00 00 	mov    rax,QWORD PTR [rip+0x86ff]        # 140010228 <__imp_InitializeCriticalSection>
   140007b29:	ff d0                	call   rax
   140007b2b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b2f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b33:	7e cc                	jle    140007b01 <dtoa_lock+0x7f>
   140007b35:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007a10 <dtoa_lock_cleanup>
   140007b3c:	48 89 c1             	mov    rcx,rax
   140007b3f:	e8 eb 9a ff ff       	call   14000162f <atexit>
   140007b44:	c7 05 a2 76 00 00 02 	mov    DWORD PTR [rip+0x76a2],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b4b:	00 00 00 
   140007b4e:	eb 20                	jmp    140007b70 <dtoa_lock+0xee>
   140007b50:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b54:	75 1a                	jne    140007b70 <dtoa_lock+0xee>
   140007b56:	c7 05 90 76 00 00 02 	mov    DWORD PTR [rip+0x7690],0x2        # 14000f1f0 <dtoa_CS_init>
   140007b5d:	00 00 00 
   140007b60:	eb 0e                	jmp    140007b70 <dtoa_lock+0xee>
   140007b62:	b9 01 00 00 00       	mov    ecx,0x1
   140007b67:	48 8b 05 e2 86 00 00 	mov    rax,QWORD PTR [rip+0x86e2]        # 140010250 <__imp_Sleep>
   140007b6e:	ff d0                	call   rax
   140007b70:	8b 05 7a 76 00 00    	mov    eax,DWORD PTR [rip+0x767a]        # 14000f1f0 <dtoa_CS_init>
   140007b76:	83 f8 01             	cmp    eax,0x1
   140007b79:	74 e7                	je     140007b62 <dtoa_lock+0xe0>
   140007b7b:	8b 05 6f 76 00 00    	mov    eax,DWORD PTR [rip+0x766f]        # 14000f1f0 <dtoa_CS_init>
   140007b81:	83 f8 02             	cmp    eax,0x2
   140007b84:	75 28                	jne    140007bae <dtoa_lock+0x12c>
   140007b86:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007b89:	48 89 d0             	mov    rax,rdx
   140007b8c:	48 c1 e0 02          	shl    rax,0x2
   140007b90:	48 01 d0             	add    rax,rdx
   140007b93:	48 c1 e0 03          	shl    rax,0x3
   140007b97:	48 8d 15 02 76 00 00 	lea    rdx,[rip+0x7602]        # 14000f1a0 <dtoa_CritSec>
   140007b9e:	48 01 d0             	add    rax,rdx
   140007ba1:	48 89 c1             	mov    rcx,rax
   140007ba4:	48 8b 05 4d 86 00 00 	mov    rax,QWORD PTR [rip+0x864d]        # 1400101f8 <__imp_EnterCriticalSection>
   140007bab:	ff d0                	call   rax
   140007bad:	90                   	nop
   140007bae:	48 83 c4 40          	add    rsp,0x40
   140007bb2:	5d                   	pop    rbp
   140007bb3:	c3                   	ret

0000000140007bb4 <dtoa_unlock>:
   140007bb4:	55                   	push   rbp
   140007bb5:	48 89 e5             	mov    rbp,rsp
   140007bb8:	48 83 ec 20          	sub    rsp,0x20
   140007bbc:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007bbf:	8b 05 2b 76 00 00    	mov    eax,DWORD PTR [rip+0x762b]        # 14000f1f0 <dtoa_CS_init>
   140007bc5:	83 f8 02             	cmp    eax,0x2
   140007bc8:	75 27                	jne    140007bf1 <dtoa_unlock+0x3d>
   140007bca:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007bcd:	48 89 d0             	mov    rax,rdx
   140007bd0:	48 c1 e0 02          	shl    rax,0x2
   140007bd4:	48 01 d0             	add    rax,rdx
   140007bd7:	48 c1 e0 03          	shl    rax,0x3
   140007bdb:	48 8d 15 be 75 00 00 	lea    rdx,[rip+0x75be]        # 14000f1a0 <dtoa_CritSec>
   140007be2:	48 01 d0             	add    rax,rdx
   140007be5:	48 89 c1             	mov    rcx,rax
   140007be8:	48 8b 05 41 86 00 00 	mov    rax,QWORD PTR [rip+0x8641]        # 140010230 <__imp_LeaveCriticalSection>
   140007bef:	ff d0                	call   rax
   140007bf1:	90                   	nop
   140007bf2:	48 83 c4 20          	add    rsp,0x20
   140007bf6:	5d                   	pop    rbp
   140007bf7:	c3                   	ret

0000000140007bf8 <__lo0bits_D2A>:
   140007bf8:	55                   	push   rbp
   140007bf9:	48 89 e5             	mov    rbp,rsp
   140007bfc:	48 83 ec 10          	sub    rsp,0x10
   140007c00:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007c04:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c08:	8b 00                	mov    eax,DWORD PTR [rax]
   140007c0a:	f3 0f bc c0          	tzcnt  eax,eax
   140007c0e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007c11:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c15:	8b 10                	mov    edx,DWORD PTR [rax]
   140007c17:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c1a:	89 c1                	mov    ecx,eax
   140007c1c:	d3 ea                	shr    edx,cl
   140007c1e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007c22:	89 10                	mov    DWORD PTR [rax],edx
   140007c24:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c27:	48 83 c4 10          	add    rsp,0x10
   140007c2b:	5d                   	pop    rbp
   140007c2c:	c3                   	ret

0000000140007c2d <__hi0bits_D2A>:
   140007c2d:	55                   	push   rbp
   140007c2e:	48 89 e5             	mov    rbp,rsp
   140007c31:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c34:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007c38:	83 f0 1f             	xor    eax,0x1f
   140007c3b:	5d                   	pop    rbp
   140007c3c:	c3                   	ret

0000000140007c3d <__Balloc_D2A>:
   140007c3d:	55                   	push   rbp
   140007c3e:	48 89 e5             	mov    rbp,rsp
   140007c41:	48 83 ec 30          	sub    rsp,0x30
   140007c45:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007c48:	b9 00 00 00 00       	mov    ecx,0x0
   140007c4d:	e8 30 fe ff ff       	call   140007a82 <dtoa_lock>
   140007c52:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007c56:	7f 48                	jg     140007ca0 <__Balloc_D2A+0x63>
   140007c58:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007c5b:	48 98                	cdqe
   140007c5d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007c64:	00 
   140007c65:	48 8d 05 94 75 00 00 	lea    rax,[rip+0x7594]        # 14000f200 <freelist>
   140007c6c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007c70:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007c74:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007c79:	74 25                	je     140007ca0 <__Balloc_D2A+0x63>
   140007c7b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007c7f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007c82:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c85:	48 63 d2             	movsxd rdx,edx
   140007c88:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007c8f:	00 
   140007c90:	48 8d 15 69 75 00 00 	lea    rdx,[rip+0x7569]        # 14000f200 <freelist>
   140007c97:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007c9b:	e9 b1 00 00 00       	jmp    140007d51 <__Balloc_D2A+0x114>
   140007ca0:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007ca3:	ba 01 00 00 00       	mov    edx,0x1
   140007ca8:	89 c1                	mov    ecx,eax
   140007caa:	d3 e2                	shl    edx,cl
   140007cac:	89 d0                	mov    eax,edx
   140007cae:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007cb1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007cb4:	83 e8 01             	sub    eax,0x1
   140007cb7:	48 98                	cdqe
   140007cb9:	48 c1 e0 02          	shl    rax,0x2
   140007cbd:	48 83 c0 27          	add    rax,0x27
   140007cc1:	48 c1 e8 03          	shr    rax,0x3
   140007cc5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007cc8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007ccc:	7f 4e                	jg     140007d1c <__Balloc_D2A+0xdf>
   140007cce:	48 8b 15 bb 23 00 00 	mov    rdx,QWORD PTR [rip+0x23bb]        # 14000a090 <pmem_next>
   140007cd5:	48 8d 05 84 75 00 00 	lea    rax,[rip+0x7584]        # 14000f260 <private_mem>
   140007cdc:	48 29 c2             	sub    rdx,rax
   140007cdf:	48 89 d0             	mov    rax,rdx
   140007ce2:	48 c1 f8 03          	sar    rax,0x3
   140007ce6:	48 89 c2             	mov    rdx,rax
   140007ce9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007cec:	48 01 d0             	add    rax,rdx
   140007cef:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007cf5:	77 25                	ja     140007d1c <__Balloc_D2A+0xdf>
   140007cf7:	48 8b 05 92 23 00 00 	mov    rax,QWORD PTR [rip+0x2392]        # 14000a090 <pmem_next>
   140007cfe:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d02:	48 8b 05 87 23 00 00 	mov    rax,QWORD PTR [rip+0x2387]        # 14000a090 <pmem_next>
   140007d09:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007d0c:	48 c1 e2 03          	shl    rdx,0x3
   140007d10:	48 01 d0             	add    rax,rdx
   140007d13:	48 89 05 76 23 00 00 	mov    QWORD PTR [rip+0x2376],rax        # 14000a090 <pmem_next>
   140007d1a:	eb 21                	jmp    140007d3d <__Balloc_D2A+0x100>
   140007d1c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007d1f:	48 c1 e0 03          	shl    rax,0x3
   140007d23:	48 89 c1             	mov    rcx,rax
   140007d26:	e8 ed 18 00 00       	call   140009618 <malloc>
   140007d2b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d2f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d34:	75 07                	jne    140007d3d <__Balloc_D2A+0x100>
   140007d36:	b8 00 00 00 00       	mov    eax,0x0
   140007d3b:	eb 3b                	jmp    140007d78 <__Balloc_D2A+0x13b>
   140007d3d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d41:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d44:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007d47:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d4b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007d4e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007d51:	b9 00 00 00 00       	mov    ecx,0x0
   140007d56:	e8 59 fe ff ff       	call   140007bb4 <dtoa_unlock>
   140007d5b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d5f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007d66:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d6a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007d6d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d71:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007d74:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d78:	48 83 c4 30          	add    rsp,0x30
   140007d7c:	5d                   	pop    rbp
   140007d7d:	c3                   	ret

0000000140007d7e <__Bfree_D2A>:
   140007d7e:	55                   	push   rbp
   140007d7f:	48 89 e5             	mov    rbp,rsp
   140007d82:	48 83 ec 20          	sub    rsp,0x20
   140007d86:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007d8a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007d8f:	74 71                	je     140007e02 <__Bfree_D2A+0x84>
   140007d91:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d95:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007d98:	83 f8 09             	cmp    eax,0x9
   140007d9b:	7e 0e                	jle    140007dab <__Bfree_D2A+0x2d>
   140007d9d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007da1:	48 89 c1             	mov    rcx,rax
   140007da4:	e8 5f 18 00 00       	call   140009608 <free>
   140007da9:	eb 57                	jmp    140007e02 <__Bfree_D2A+0x84>
   140007dab:	b9 00 00 00 00       	mov    ecx,0x0
   140007db0:	e8 cd fc ff ff       	call   140007a82 <dtoa_lock>
   140007db5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007db9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007dbc:	48 98                	cdqe
   140007dbe:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007dc5:	00 
   140007dc6:	48 8d 05 33 74 00 00 	lea    rax,[rip+0x7433]        # 14000f200 <freelist>
   140007dcd:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007dd1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007dd5:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007dd8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ddc:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ddf:	48 98                	cdqe
   140007de1:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007de8:	00 
   140007de9:	48 8d 15 10 74 00 00 	lea    rdx,[rip+0x7410]        # 14000f200 <freelist>
   140007df0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007df4:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007df8:	b9 00 00 00 00       	mov    ecx,0x0
   140007dfd:	e8 b2 fd ff ff       	call   140007bb4 <dtoa_unlock>
   140007e02:	90                   	nop
   140007e03:	48 83 c4 20          	add    rsp,0x20
   140007e07:	5d                   	pop    rbp
   140007e08:	c3                   	ret

0000000140007e09 <__multadd_D2A>:
   140007e09:	55                   	push   rbp
   140007e0a:	48 89 e5             	mov    rbp,rsp
   140007e0d:	48 83 ec 50          	sub    rsp,0x50
   140007e11:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e15:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007e18:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007e1c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e20:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007e23:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007e26:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e2a:	48 83 c0 18          	add    rax,0x18
   140007e2e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007e32:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007e39:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007e3c:	48 98                	cdqe
   140007e3e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e42:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e46:	8b 00                	mov    eax,DWORD PTR [rax]
   140007e48:	89 c2                	mov    edx,eax
   140007e4a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007e4d:	48 98                	cdqe
   140007e4f:	48 0f af d0          	imul   rdx,rax
   140007e53:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007e57:	48 01 d0             	add    rax,rdx
   140007e5a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007e5e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007e62:	48 c1 e8 20          	shr    rax,0x20
   140007e66:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007e6a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007e6e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007e72:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007e76:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007e7a:	89 10                	mov    DWORD PTR [rax],edx
   140007e7c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007e80:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007e83:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007e86:	7c ba                	jl     140007e42 <__multadd_D2A+0x39>
   140007e88:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007e8d:	0f 84 9a 00 00 00    	je     140007f2d <__multadd_D2A+0x124>
   140007e93:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007e97:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007e9a:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007e9d:	7c 67                	jl     140007f06 <__multadd_D2A+0xfd>
   140007e9f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ea3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ea6:	83 c0 01             	add    eax,0x1
   140007ea9:	89 c1                	mov    ecx,eax
   140007eab:	e8 8d fd ff ff       	call   140007c3d <__Balloc_D2A>
   140007eb0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007eb4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007eb9:	75 07                	jne    140007ec2 <__multadd_D2A+0xb9>
   140007ebb:	b8 00 00 00 00       	mov    eax,0x0
   140007ec0:	eb 6f                	jmp    140007f31 <__multadd_D2A+0x128>
   140007ec2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ec6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ec9:	48 98                	cdqe
   140007ecb:	48 83 c0 02          	add    rax,0x2
   140007ecf:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007ed6:	00 
   140007ed7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007edb:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007edf:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007ee3:	48 83 c0 10          	add    rax,0x10
   140007ee7:	49 89 c8             	mov    r8,rcx
   140007eea:	48 89 c1             	mov    rcx,rax
   140007eed:	e8 2e 17 00 00       	call   140009620 <memcpy>
   140007ef2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ef6:	48 89 c1             	mov    rcx,rax
   140007ef9:	e8 80 fe ff ff       	call   140007d7e <__Bfree_D2A>
   140007efe:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007f02:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007f06:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140007f09:	8d 50 01             	lea    edx,[rax+0x1]
   140007f0c:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   140007f0f:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140007f13:	89 d1                	mov    ecx,edx
   140007f15:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007f19:	48 98                	cdqe
   140007f1b:	48 83 c0 04          	add    rax,0x4
   140007f1f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140007f23:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f27:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140007f2a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007f2d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f31:	48 83 c4 50          	add    rsp,0x50
   140007f35:	5d                   	pop    rbp
   140007f36:	c3                   	ret

0000000140007f37 <__i2b_D2A>:
   140007f37:	55                   	push   rbp
   140007f38:	48 89 e5             	mov    rbp,rsp
   140007f3b:	48 83 ec 30          	sub    rsp,0x30
   140007f3f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007f42:	b9 01 00 00 00       	mov    ecx,0x1
   140007f47:	e8 f1 fc ff ff       	call   140007c3d <__Balloc_D2A>
   140007f4c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007f50:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007f55:	75 07                	jne    140007f5e <__i2b_D2A+0x27>
   140007f57:	b8 00 00 00 00       	mov    eax,0x0
   140007f5c:	eb 19                	jmp    140007f77 <__i2b_D2A+0x40>
   140007f5e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007f61:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f65:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140007f68:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f6c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140007f73:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007f77:	48 83 c4 30          	add    rsp,0x30
   140007f7b:	5d                   	pop    rbp
   140007f7c:	c3                   	ret

0000000140007f7d <__mult_D2A>:
   140007f7d:	55                   	push   rbp
   140007f7e:	48 89 e5             	mov    rbp,rsp
   140007f81:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140007f88:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007f8c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140007f90:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f94:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007f97:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007f9b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f9e:	39 c2                	cmp    edx,eax
   140007fa0:	7d 18                	jge    140007fba <__mult_D2A+0x3d>
   140007fa2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fa6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140007faa:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fae:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007fb2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140007fb6:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007fba:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fbe:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007fc1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007fc4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fc8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fcb:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   140007fce:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007fd2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fd5:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   140007fd8:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140007fdb:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140007fde:	01 d0                	add    eax,edx
   140007fe0:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007fe3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fe7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007fea:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   140007fed:	7e 04                	jle    140007ff3 <__mult_D2A+0x76>
   140007fef:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007ff3:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007ff6:	89 c1                	mov    ecx,eax
   140007ff8:	e8 40 fc ff ff       	call   140007c3d <__Balloc_D2A>
   140007ffd:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008001:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140008006:	75 0a                	jne    140008012 <__mult_D2A+0x95>
   140008008:	b8 00 00 00 00       	mov    eax,0x0
   14000800d:	e9 88 01 00 00       	jmp    14000819a <__mult_D2A+0x21d>
   140008012:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008016:	48 83 c0 18          	add    rax,0x18
   14000801a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000801e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008021:	48 98                	cdqe
   140008023:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000802a:	00 
   14000802b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000802f:	48 01 d0             	add    rax,rdx
   140008032:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008036:	eb 0f                	jmp    140008047 <__mult_D2A+0xca>
   140008038:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000803c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008042:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008047:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000804b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000804f:	72 e7                	jb     140008038 <__mult_D2A+0xbb>
   140008051:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008055:	48 83 c0 18          	add    rax,0x18
   140008059:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000805d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008060:	48 98                	cdqe
   140008062:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008069:	00 
   14000806a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000806e:	48 01 d0             	add    rax,rdx
   140008071:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008075:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008079:	48 83 c0 18          	add    rax,0x18
   14000807d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008081:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008084:	48 98                	cdqe
   140008086:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000808d:	00 
   14000808e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008092:	48 01 d0             	add    rax,rdx
   140008095:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   140008099:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000809d:	48 83 c0 18          	add    rax,0x18
   1400080a1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400080a5:	e9 95 00 00 00       	jmp    14000813f <__mult_D2A+0x1c2>
   1400080aa:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400080ae:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400080b2:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400080b6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080b8:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400080bb:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   1400080bf:	74 79                	je     14000813a <__mult_D2A+0x1bd>
   1400080c1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400080c5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400080c9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400080cd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400080d1:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400080d8:	00 
   1400080d9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400080dd:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400080e1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400080e5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080e7:	89 c2                	mov    edx,eax
   1400080e9:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400080ec:	48 0f af d0          	imul   rdx,rax
   1400080f0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400080f4:	8b 00                	mov    eax,DWORD PTR [rax]
   1400080f6:	89 c0                	mov    eax,eax
   1400080f8:	48 01 c2             	add    rdx,rax
   1400080fb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400080ff:	48 01 d0             	add    rax,rdx
   140008102:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140008106:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   14000810a:	48 c1 e8 20          	shr    rax,0x20
   14000810e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008112:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008116:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000811a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000811e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008122:	89 10                	mov    DWORD PTR [rax],edx
   140008124:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008128:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000812c:	72 ab                	jb     1400080d9 <__mult_D2A+0x15c>
   14000812e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008132:	89 c2                	mov    edx,eax
   140008134:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008138:	89 10                	mov    DWORD PTR [rax],edx
   14000813a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000813f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008143:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008147:	0f 82 5d ff ff ff    	jb     1400080aa <__mult_D2A+0x12d>
   14000814d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008151:	48 83 c0 18          	add    rax,0x18
   140008155:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008159:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000815c:	48 98                	cdqe
   14000815e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008165:	00 
   140008166:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000816a:	48 01 d0             	add    rax,rdx
   14000816d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008171:	eb 04                	jmp    140008177 <__mult_D2A+0x1fa>
   140008173:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008177:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000817b:	7e 0f                	jle    14000818c <__mult_D2A+0x20f>
   14000817d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008182:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008186:	8b 00                	mov    eax,DWORD PTR [rax]
   140008188:	85 c0                	test   eax,eax
   14000818a:	74 e7                	je     140008173 <__mult_D2A+0x1f6>
   14000818c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008190:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140008193:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008196:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   14000819a:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400081a1:	5d                   	pop    rbp
   1400081a2:	c3                   	ret

00000001400081a3 <__pow5mult_D2A>:
   1400081a3:	55                   	push   rbp
   1400081a4:	48 89 e5             	mov    rbp,rsp
   1400081a7:	48 83 ec 40          	sub    rsp,0x40
   1400081ab:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400081af:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400081b2:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400081b5:	83 e0 03             	and    eax,0x3
   1400081b8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400081bb:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400081bf:	74 41                	je     140008202 <__pow5mult_D2A+0x5f>
   1400081c1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400081c4:	83 e8 01             	sub    eax,0x1
   1400081c7:	48 98                	cdqe
   1400081c9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400081d0:	00 
   1400081d1:	48 8d 05 c0 1e 00 00 	lea    rax,[rip+0x1ec0]        # 14000a098 <p05.0>
   1400081d8:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   1400081db:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400081df:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400081e5:	48 89 c1             	mov    rcx,rax
   1400081e8:	e8 1c fc ff ff       	call   140007e09 <__multadd_D2A>
   1400081ed:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400081f1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400081f6:	75 0a                	jne    140008202 <__pow5mult_D2A+0x5f>
   1400081f8:	b8 00 00 00 00       	mov    eax,0x0
   1400081fd:	e9 58 01 00 00       	jmp    14000835a <__pow5mult_D2A+0x1b7>
   140008202:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   140008206:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000820a:	75 09                	jne    140008215 <__pow5mult_D2A+0x72>
   14000820c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008210:	e9 45 01 00 00       	jmp    14000835a <__pow5mult_D2A+0x1b7>
   140008215:	48 8b 05 44 79 00 00 	mov    rax,QWORD PTR [rip+0x7944]        # 14000fb60 <p5s>
   14000821c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008220:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008225:	75 5e                	jne    140008285 <__pow5mult_D2A+0xe2>
   140008227:	b9 01 00 00 00       	mov    ecx,0x1
   14000822c:	e8 51 f8 ff ff       	call   140007a82 <dtoa_lock>
   140008231:	48 8b 05 28 79 00 00 	mov    rax,QWORD PTR [rip+0x7928]        # 14000fb60 <p5s>
   140008238:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000823c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008241:	75 38                	jne    14000827b <__pow5mult_D2A+0xd8>
   140008243:	b9 71 02 00 00       	mov    ecx,0x271
   140008248:	e8 ea fc ff ff       	call   140007f37 <__i2b_D2A>
   14000824d:	48 89 05 0c 79 00 00 	mov    QWORD PTR [rip+0x790c],rax        # 14000fb60 <p5s>
   140008254:	48 8b 05 05 79 00 00 	mov    rax,QWORD PTR [rip+0x7905]        # 14000fb60 <p5s>
   14000825b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000825f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008264:	75 0a                	jne    140008270 <__pow5mult_D2A+0xcd>
   140008266:	b8 00 00 00 00       	mov    eax,0x0
   14000826b:	e9 ea 00 00 00       	jmp    14000835a <__pow5mult_D2A+0x1b7>
   140008270:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008274:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000827b:	b9 01 00 00 00       	mov    ecx,0x1
   140008280:	e8 2f f9 ff ff       	call   140007bb4 <dtoa_unlock>
   140008285:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008288:	83 e0 01             	and    eax,0x1
   14000828b:	85 c0                	test   eax,eax
   14000828d:	74 39                	je     1400082c8 <__pow5mult_D2A+0x125>
   14000828f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008293:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008297:	48 89 c1             	mov    rcx,rax
   14000829a:	e8 de fc ff ff       	call   140007f7d <__mult_D2A>
   14000829f:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400082a3:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   1400082a8:	75 0a                	jne    1400082b4 <__pow5mult_D2A+0x111>
   1400082aa:	b8 00 00 00 00       	mov    eax,0x0
   1400082af:	e9 a6 00 00 00       	jmp    14000835a <__pow5mult_D2A+0x1b7>
   1400082b4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082b8:	48 89 c1             	mov    rcx,rax
   1400082bb:	e8 be fa ff ff       	call   140007d7e <__Bfree_D2A>
   1400082c0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400082c4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400082c8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400082cb:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400082cf:	0f 84 80 00 00 00    	je     140008355 <__pow5mult_D2A+0x1b2>
   1400082d5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082d9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400082dc:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400082e0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400082e5:	75 61                	jne    140008348 <__pow5mult_D2A+0x1a5>
   1400082e7:	b9 01 00 00 00       	mov    ecx,0x1
   1400082ec:	e8 91 f7 ff ff       	call   140007a82 <dtoa_lock>
   1400082f1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400082f5:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400082f8:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400082fc:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008301:	75 3b                	jne    14000833e <__pow5mult_D2A+0x19b>
   140008303:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008307:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000830b:	48 89 c1             	mov    rcx,rax
   14000830e:	e8 6a fc ff ff       	call   140007f7d <__mult_D2A>
   140008313:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008317:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000831a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000831e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008321:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008325:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000832a:	75 07                	jne    140008333 <__pow5mult_D2A+0x190>
   14000832c:	b8 00 00 00 00       	mov    eax,0x0
   140008331:	eb 27                	jmp    14000835a <__pow5mult_D2A+0x1b7>
   140008333:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008337:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000833e:	b9 01 00 00 00       	mov    ecx,0x1
   140008343:	e8 6c f8 ff ff       	call   140007bb4 <dtoa_unlock>
   140008348:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000834c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008350:	e9 30 ff ff ff       	jmp    140008285 <__pow5mult_D2A+0xe2>
   140008355:	90                   	nop
   140008356:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000835a:	48 83 c4 40          	add    rsp,0x40
   14000835e:	5d                   	pop    rbp
   14000835f:	c3                   	ret

0000000140008360 <__lshift_D2A>:
   140008360:	55                   	push   rbp
   140008361:	48 89 e5             	mov    rbp,rsp
   140008364:	48 83 ec 60          	sub    rsp,0x60
   140008368:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000836c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000836f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008372:	c1 f8 05             	sar    eax,0x5
   140008375:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008378:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000837c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000837f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008382:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008386:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008389:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000838c:	01 d0                	add    eax,edx
   14000838e:	83 c0 01             	add    eax,0x1
   140008391:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008394:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008398:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000839b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000839e:	eb 07                	jmp    1400083a7 <__lshift_D2A+0x47>
   1400083a0:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400083a4:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400083a7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400083aa:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   1400083ad:	7f f1                	jg     1400083a0 <__lshift_D2A+0x40>
   1400083af:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400083b2:	89 c1                	mov    ecx,eax
   1400083b4:	e8 84 f8 ff ff       	call   140007c3d <__Balloc_D2A>
   1400083b9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400083bd:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400083c2:	75 0a                	jne    1400083ce <__lshift_D2A+0x6e>
   1400083c4:	b8 00 00 00 00       	mov    eax,0x0
   1400083c9:	e9 19 01 00 00       	jmp    1400084e7 <__lshift_D2A+0x187>
   1400083ce:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400083d2:	48 83 c0 18          	add    rax,0x18
   1400083d6:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400083da:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400083e1:	eb 16                	jmp    1400083f9 <__lshift_D2A+0x99>
   1400083e3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400083e7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400083eb:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400083ef:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400083f5:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   1400083f9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400083fc:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   1400083ff:	7c e2                	jl     1400083e3 <__lshift_D2A+0x83>
   140008401:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008405:	48 83 c0 18          	add    rax,0x18
   140008409:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000840d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008411:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008414:	48 98                	cdqe
   140008416:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000841d:	00 
   14000841e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008422:	48 01 d0             	add    rax,rdx
   140008425:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008429:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000842d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008431:	74 71                	je     1400084a4 <__lshift_D2A+0x144>
   140008433:	b8 20 00 00 00       	mov    eax,0x20
   140008438:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000843b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000843e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008445:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008449:	8b 10                	mov    edx,DWORD PTR [rax]
   14000844b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000844e:	89 c1                	mov    ecx,eax
   140008450:	d3 e2                	shl    edx,cl
   140008452:	89 d1                	mov    ecx,edx
   140008454:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008458:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000845c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008460:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008463:	89 ca                	mov    edx,ecx
   140008465:	89 10                	mov    DWORD PTR [rax],edx
   140008467:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000846b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000846f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008473:	8b 10                	mov    edx,DWORD PTR [rax]
   140008475:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008478:	89 c1                	mov    ecx,eax
   14000847a:	d3 ea                	shr    edx,cl
   14000847c:	89 d0                	mov    eax,edx
   14000847e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008481:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008485:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008489:	72 ba                	jb     140008445 <__lshift_D2A+0xe5>
   14000848b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000848f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   140008492:	89 10                	mov    DWORD PTR [rax],edx
   140008494:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008498:	8b 00                	mov    eax,DWORD PTR [rax]
   14000849a:	85 c0                	test   eax,eax
   14000849c:	74 2c                	je     1400084ca <__lshift_D2A+0x16a>
   14000849e:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   1400084a2:	eb 26                	jmp    1400084ca <__lshift_D2A+0x16a>
   1400084a4:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400084a8:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400084ac:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400084b0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084b4:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400084b8:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   1400084bc:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400084be:	89 10                	mov    DWORD PTR [rax],edx
   1400084c0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400084c4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400084c8:	72 da                	jb     1400084a4 <__lshift_D2A+0x144>
   1400084ca:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400084cd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400084d0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084d4:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400084d7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084db:	48 89 c1             	mov    rcx,rax
   1400084de:	e8 9b f8 ff ff       	call   140007d7e <__Bfree_D2A>
   1400084e3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084e7:	48 83 c4 60          	add    rsp,0x60
   1400084eb:	5d                   	pop    rbp
   1400084ec:	c3                   	ret

00000001400084ed <__cmp_D2A>:
   1400084ed:	55                   	push   rbp
   1400084ee:	48 89 e5             	mov    rbp,rsp
   1400084f1:	48 83 ec 30          	sub    rsp,0x30
   1400084f5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400084f9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400084fd:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008501:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008504:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140008507:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000850b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000850e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008511:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008514:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008517:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000851b:	74 08                	je     140008525 <__cmp_D2A+0x38>
   14000851d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008520:	e9 92 00 00 00       	jmp    1400085b7 <__cmp_D2A+0xca>
   140008525:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008529:	48 83 c0 18          	add    rax,0x18
   14000852d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008531:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008534:	48 98                	cdqe
   140008536:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000853d:	00 
   14000853e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008542:	48 01 d0             	add    rax,rdx
   140008545:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008549:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000854d:	48 83 c0 18          	add    rax,0x18
   140008551:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008555:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008558:	48 98                	cdqe
   14000855a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008561:	00 
   140008562:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008566:	48 01 d0             	add    rax,rdx
   140008569:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000856d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008572:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008576:	8b 10                	mov    edx,DWORD PTR [rax]
   140008578:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000857d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008581:	8b 00                	mov    eax,DWORD PTR [rax]
   140008583:	39 c2                	cmp    edx,eax
   140008585:	74 1e                	je     1400085a5 <__cmp_D2A+0xb8>
   140008587:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000858b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000858d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008591:	8b 00                	mov    eax,DWORD PTR [rax]
   140008593:	39 c2                	cmp    edx,eax
   140008595:	73 07                	jae    14000859e <__cmp_D2A+0xb1>
   140008597:	b8 ff ff ff ff       	mov    eax,0xffffffff
   14000859c:	eb 19                	jmp    1400085b7 <__cmp_D2A+0xca>
   14000859e:	b8 01 00 00 00       	mov    eax,0x1
   1400085a3:	eb 12                	jmp    1400085b7 <__cmp_D2A+0xca>
   1400085a5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400085a9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400085ad:	73 02                	jae    1400085b1 <__cmp_D2A+0xc4>
   1400085af:	eb bc                	jmp    14000856d <__cmp_D2A+0x80>
   1400085b1:	90                   	nop
   1400085b2:	b8 00 00 00 00       	mov    eax,0x0
   1400085b7:	48 83 c4 30          	add    rsp,0x30
   1400085bb:	5d                   	pop    rbp
   1400085bc:	c3                   	ret

00000001400085bd <__diff_D2A>:
   1400085bd:	55                   	push   rbp
   1400085be:	48 89 e5             	mov    rbp,rsp
   1400085c1:	48 83 ec 70          	sub    rsp,0x70
   1400085c5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400085c9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400085cd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400085d1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085d5:	48 89 c1             	mov    rcx,rax
   1400085d8:	e8 10 ff ff ff       	call   1400084ed <__cmp_D2A>
   1400085dd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400085e0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400085e4:	75 3e                	jne    140008624 <__diff_D2A+0x67>
   1400085e6:	b9 00 00 00 00       	mov    ecx,0x0
   1400085eb:	e8 4d f6 ff ff       	call   140007c3d <__Balloc_D2A>
   1400085f0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400085f4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400085f9:	75 0a                	jne    140008605 <__diff_D2A+0x48>
   1400085fb:	b8 00 00 00 00       	mov    eax,0x0
   140008600:	e9 ab 01 00 00       	jmp    1400087b0 <__diff_D2A+0x1f3>
   140008605:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008609:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008610:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008614:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000861b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000861f:	e9 8c 01 00 00       	jmp    1400087b0 <__diff_D2A+0x1f3>
   140008624:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008628:	79 21                	jns    14000864b <__diff_D2A+0x8e>
   14000862a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000862e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008632:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008636:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000863a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000863e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008642:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008649:	eb 07                	jmp    140008652 <__diff_D2A+0x95>
   14000864b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008652:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008656:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008659:	89 c1                	mov    ecx,eax
   14000865b:	e8 dd f5 ff ff       	call   140007c3d <__Balloc_D2A>
   140008660:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008664:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008669:	75 0a                	jne    140008675 <__diff_D2A+0xb8>
   14000866b:	b8 00 00 00 00       	mov    eax,0x0
   140008670:	e9 3b 01 00 00       	jmp    1400087b0 <__diff_D2A+0x1f3>
   140008675:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008679:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000867c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000867f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008683:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008686:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008689:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000868d:	48 83 c0 18          	add    rax,0x18
   140008691:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008695:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008698:	48 98                	cdqe
   14000869a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400086a1:	00 
   1400086a2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086a6:	48 01 d0             	add    rax,rdx
   1400086a9:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400086ad:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086b1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400086b4:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400086b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400086bb:	48 83 c0 18          	add    rax,0x18
   1400086bf:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400086c3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400086c6:	48 98                	cdqe
   1400086c8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400086cf:	00 
   1400086d0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400086d4:	48 01 d0             	add    rax,rdx
   1400086d7:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400086db:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400086df:	48 83 c0 18          	add    rax,0x18
   1400086e3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400086e7:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400086ee:	00 
   1400086ef:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086f3:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400086f7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400086fb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400086fd:	89 c1                	mov    ecx,eax
   1400086ff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008703:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008707:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   14000870b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000870d:	89 c2                	mov    edx,eax
   14000870f:	48 89 c8             	mov    rax,rcx
   140008712:	48 29 d0             	sub    rax,rdx
   140008715:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008719:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000871d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008721:	48 c1 e8 20          	shr    rax,0x20
   140008725:	83 e0 01             	and    eax,0x1
   140008728:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000872c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008730:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008734:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008738:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000873c:	89 10                	mov    DWORD PTR [rax],edx
   14000873e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008742:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008746:	72 a7                	jb     1400086ef <__diff_D2A+0x132>
   140008748:	eb 39                	jmp    140008783 <__diff_D2A+0x1c6>
   14000874a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000874e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008752:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008756:	8b 00                	mov    eax,DWORD PTR [rax]
   140008758:	89 c0                	mov    eax,eax
   14000875a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000875e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008762:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008766:	48 c1 e8 20          	shr    rax,0x20
   14000876a:	83 e0 01             	and    eax,0x1
   14000876d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008771:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008775:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008779:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000877d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008781:	89 10                	mov    DWORD PTR [rax],edx
   140008783:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008787:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000878b:	72 bd                	jb     14000874a <__diff_D2A+0x18d>
   14000878d:	eb 04                	jmp    140008793 <__diff_D2A+0x1d6>
   14000878f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008793:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008798:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000879c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000879e:	85 c0                	test   eax,eax
   1400087a0:	74 ed                	je     14000878f <__diff_D2A+0x1d2>
   1400087a2:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087a6:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400087a9:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400087ac:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087b0:	48 83 c4 70          	add    rsp,0x70
   1400087b4:	5d                   	pop    rbp
   1400087b5:	c3                   	ret

00000001400087b6 <__b2d_D2A>:
   1400087b6:	55                   	push   rbp
   1400087b7:	48 89 e5             	mov    rbp,rsp
   1400087ba:	48 83 ec 50          	sub    rsp,0x50
   1400087be:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400087c2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400087c6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087ca:	48 83 c0 18          	add    rax,0x18
   1400087ce:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400087d2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400087d6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400087d9:	48 98                	cdqe
   1400087db:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087e2:	00 
   1400087e3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400087e7:	48 01 d0             	add    rax,rdx
   1400087ea:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400087ee:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400087f3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400087f7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400087f9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400087fc:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400087ff:	89 c1                	mov    ecx,eax
   140008801:	e8 27 f4 ff ff       	call   140007c2d <__hi0bits_D2A>
   140008806:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008809:	b8 20 00 00 00       	mov    eax,0x20
   14000880e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008811:	89 c2                	mov    edx,eax
   140008813:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008817:	89 10                	mov    DWORD PTR [rax],edx
   140008819:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000881d:	7f 66                	jg     140008885 <__b2d_D2A+0xcf>
   14000881f:	b8 0b 00 00 00       	mov    eax,0xb
   140008824:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008827:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000882a:	89 c1                	mov    ecx,eax
   14000882c:	d3 ea                	shr    edx,cl
   14000882e:	89 d0                	mov    eax,edx
   140008830:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008835:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008838:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000883c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008840:	73 10                	jae    140008852 <__b2d_D2A+0x9c>
   140008842:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008847:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000884b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000884d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008850:	eb 07                	jmp    140008859 <__b2d_D2A+0xa3>
   140008852:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008859:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000885c:	83 c0 15             	add    eax,0x15
   14000885f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008862:	89 c1                	mov    ecx,eax
   140008864:	d3 e2                	shl    edx,cl
   140008866:	41 89 d0             	mov    r8d,edx
   140008869:	b8 0b 00 00 00       	mov    eax,0xb
   14000886e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008871:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008874:	89 c1                	mov    ecx,eax
   140008876:	d3 ea                	shr    edx,cl
   140008878:	89 d0                	mov    eax,edx
   14000887a:	44 09 c0             	or     eax,r8d
   14000887d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008880:	e9 ac 00 00 00       	jmp    140008931 <__b2d_D2A+0x17b>
   140008885:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008889:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000888d:	73 10                	jae    14000889f <__b2d_D2A+0xe9>
   14000888f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008894:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008898:	8b 00                	mov    eax,DWORD PTR [rax]
   14000889a:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   14000889d:	eb 07                	jmp    1400088a6 <__b2d_D2A+0xf0>
   14000889f:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   1400088a6:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   1400088aa:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   1400088ae:	74 70                	je     140008920 <__b2d_D2A+0x16a>
   1400088b0:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088b3:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400088b6:	89 c1                	mov    ecx,eax
   1400088b8:	d3 e2                	shl    edx,cl
   1400088ba:	41 89 d0             	mov    r8d,edx
   1400088bd:	b8 20 00 00 00       	mov    eax,0x20
   1400088c2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400088c5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400088c8:	89 c1                	mov    ecx,eax
   1400088ca:	d3 ea                	shr    edx,cl
   1400088cc:	89 d0                	mov    eax,edx
   1400088ce:	44 09 c0             	or     eax,r8d
   1400088d1:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400088d6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400088d9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088dd:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400088e1:	73 10                	jae    1400088f3 <__b2d_D2A+0x13d>
   1400088e3:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400088e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400088ec:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088ee:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   1400088f1:	eb 07                	jmp    1400088fa <__b2d_D2A+0x144>
   1400088f3:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   1400088fa:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400088fd:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008900:	89 c1                	mov    ecx,eax
   140008902:	d3 e2                	shl    edx,cl
   140008904:	41 89 d0             	mov    r8d,edx
   140008907:	b8 20 00 00 00       	mov    eax,0x20
   14000890c:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   14000890f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008912:	89 c1                	mov    ecx,eax
   140008914:	d3 ea                	shr    edx,cl
   140008916:	89 d0                	mov    eax,edx
   140008918:	44 09 c0             	or     eax,r8d
   14000891b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   14000891e:	eb 11                	jmp    140008931 <__b2d_D2A+0x17b>
   140008920:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008923:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008928:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   14000892b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   14000892e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008931:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008936:	48 83 c4 50          	add    rsp,0x50
   14000893a:	5d                   	pop    rbp
   14000893b:	c3                   	ret

000000014000893c <__d2b_D2A>:
   14000893c:	55                   	push   rbp
   14000893d:	53                   	push   rbx
   14000893e:	48 83 ec 58          	sub    rsp,0x58
   140008942:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008947:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   14000894c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008950:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008954:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008959:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   14000895e:	b9 01 00 00 00       	mov    ecx,0x1
   140008963:	e8 d5 f2 ff ff       	call   140007c3d <__Balloc_D2A>
   140008968:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000896c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008971:	75 0a                	jne    14000897d <__d2b_D2A+0x41>
   140008973:	b8 00 00 00 00       	mov    eax,0x0
   140008978:	e9 68 01 00 00       	jmp    140008ae5 <__d2b_D2A+0x1a9>
   14000897d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008981:	48 83 c0 18          	add    rax,0x18
   140008985:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008989:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000898c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008991:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008994:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008997:	25 ff ff ff 7f       	and    eax,0x7fffffff
   14000899c:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   14000899f:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089a2:	c1 e8 14             	shr    eax,0x14
   1400089a5:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400089a8:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400089ac:	74 0b                	je     1400089b9 <__d2b_D2A+0x7d>
   1400089ae:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   1400089b1:	0d 00 00 10 00       	or     eax,0x100000
   1400089b6:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400089b9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   1400089bc:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089bf:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400089c2:	85 c0                	test   eax,eax
   1400089c4:	74 7b                	je     140008a41 <__d2b_D2A+0x105>
   1400089c6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   1400089ca:	48 89 c1             	mov    rcx,rax
   1400089cd:	e8 26 f2 ff ff       	call   140007bf8 <__lo0bits_D2A>
   1400089d2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400089d5:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   1400089d9:	74 2b                	je     140008a06 <__d2b_D2A+0xca>
   1400089db:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   1400089de:	b8 20 00 00 00       	mov    eax,0x20
   1400089e3:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   1400089e6:	89 c1                	mov    ecx,eax
   1400089e8:	d3 e2                	shl    edx,cl
   1400089ea:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400089ed:	09 c2                	or     edx,eax
   1400089ef:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400089f3:	89 10                	mov    DWORD PTR [rax],edx
   1400089f5:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   1400089f8:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400089fb:	89 c1                	mov    ecx,eax
   1400089fd:	d3 ea                	shr    edx,cl
   1400089ff:	89 d0                	mov    eax,edx
   140008a01:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a04:	eb 09                	jmp    140008a0f <__d2b_D2A+0xd3>
   140008a06:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008a09:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a0d:	89 10                	mov    DWORD PTR [rax],edx
   140008a0f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a13:	48 83 c0 04          	add    rax,0x4
   140008a17:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a1a:	89 10                	mov    DWORD PTR [rax],edx
   140008a1c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008a1e:	85 c0                	test   eax,eax
   140008a20:	74 07                	je     140008a29 <__d2b_D2A+0xed>
   140008a22:	ba 02 00 00 00       	mov    edx,0x2
   140008a27:	eb 05                	jmp    140008a2e <__d2b_D2A+0xf2>
   140008a29:	ba 01 00 00 00       	mov    edx,0x1
   140008a2e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a32:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008a35:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a39:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a3c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a3f:	eb 31                	jmp    140008a72 <__d2b_D2A+0x136>
   140008a41:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008a45:	48 89 c1             	mov    rcx,rax
   140008a48:	e8 ab f1 ff ff       	call   140007bf8 <__lo0bits_D2A>
   140008a4d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008a50:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008a53:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008a57:	89 10                	mov    DWORD PTR [rax],edx
   140008a59:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a5d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008a64:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a68:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008a6b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008a6e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008a72:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008a76:	74 26                	je     140008a9e <__d2b_D2A+0x162>
   140008a78:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008a7b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008a81:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008a84:	01 c2                	add    edx,eax
   140008a86:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008a8a:	89 10                	mov    DWORD PTR [rax],edx
   140008a8c:	b8 35 00 00 00       	mov    eax,0x35
   140008a91:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008a94:	89 c2                	mov    edx,eax
   140008a96:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008a9a:	89 10                	mov    DWORD PTR [rax],edx
   140008a9c:	eb 43                	jmp    140008ae1 <__d2b_D2A+0x1a5>
   140008a9e:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008aa1:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008aa7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008aaa:	01 c2                	add    edx,eax
   140008aac:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008ab0:	89 10                	mov    DWORD PTR [rax],edx
   140008ab2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ab5:	c1 e0 05             	shl    eax,0x5
   140008ab8:	89 c3                	mov    ebx,eax
   140008aba:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008abd:	48 98                	cdqe
   140008abf:	48 c1 e0 02          	shl    rax,0x2
   140008ac3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008ac7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008acb:	48 01 d0             	add    rax,rdx
   140008ace:	8b 00                	mov    eax,DWORD PTR [rax]
   140008ad0:	89 c1                	mov    ecx,eax
   140008ad2:	e8 56 f1 ff ff       	call   140007c2d <__hi0bits_D2A>
   140008ad7:	29 c3                	sub    ebx,eax
   140008ad9:	89 da                	mov    edx,ebx
   140008adb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008adf:	89 10                	mov    DWORD PTR [rax],edx
   140008ae1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008ae5:	48 83 c4 58          	add    rsp,0x58
   140008ae9:	5b                   	pop    rbx
   140008aea:	5d                   	pop    rbp
   140008aeb:	c3                   	ret

0000000140008aec <__strcp_D2A>:
   140008aec:	55                   	push   rbp
   140008aed:	48 89 e5             	mov    rbp,rsp
   140008af0:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008af4:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008af8:	eb 05                	jmp    140008aff <__strcp_D2A+0x13>
   140008afa:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008aff:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008b03:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008b07:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008b0b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008b0e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b12:	88 10                	mov    BYTE PTR [rax],dl
   140008b14:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b18:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008b1b:	84 c0                	test   al,al
   140008b1d:	75 db                	jne    140008afa <__strcp_D2A+0xe>
   140008b1f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008b23:	5d                   	pop    rbp
   140008b24:	c3                   	ret
   140008b25:	90                   	nop
   140008b26:	90                   	nop
   140008b27:	90                   	nop
   140008b28:	90                   	nop
   140008b29:	90                   	nop
   140008b2a:	90                   	nop
   140008b2b:	90                   	nop
   140008b2c:	90                   	nop
   140008b2d:	90                   	nop
   140008b2e:	90                   	nop
   140008b2f:	90                   	nop

0000000140008b30 <__fpclassify>:
   140008b30:	55                   	push   rbp
   140008b31:	48 89 e5             	mov    rbp,rsp
   140008b34:	48 83 ec 10          	sub    rsp,0x10
   140008b38:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008b3d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008b42:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008b47:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008b4a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b4d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008b50:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008b53:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008b59:	09 d0                	or     eax,edx
   140008b5b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b5e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008b65:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008b68:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008b6b:	85 c0                	test   eax,eax
   140008b6d:	75 07                	jne    140008b76 <__fpclassify+0x46>
   140008b6f:	b8 00 40 00 00       	mov    eax,0x4000
   140008b74:	eb 2f                	jmp    140008ba5 <__fpclassify+0x75>
   140008b76:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008b7a:	75 07                	jne    140008b83 <__fpclassify+0x53>
   140008b7c:	b8 00 44 00 00       	mov    eax,0x4400
   140008b81:	eb 22                	jmp    140008ba5 <__fpclassify+0x75>
   140008b83:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008b8a:	75 14                	jne    140008ba0 <__fpclassify+0x70>
   140008b8c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008b90:	74 07                	je     140008b99 <__fpclassify+0x69>
   140008b92:	b8 00 01 00 00       	mov    eax,0x100
   140008b97:	eb 0c                	jmp    140008ba5 <__fpclassify+0x75>
   140008b99:	b8 00 05 00 00       	mov    eax,0x500
   140008b9e:	eb 05                	jmp    140008ba5 <__fpclassify+0x75>
   140008ba0:	b8 00 04 00 00       	mov    eax,0x400
   140008ba5:	48 83 c4 10          	add    rsp,0x10
   140008ba9:	5d                   	pop    rbp
   140008baa:	c3                   	ret
   140008bab:	90                   	nop
   140008bac:	90                   	nop
   140008bad:	90                   	nop
   140008bae:	90                   	nop
   140008baf:	90                   	nop

0000000140008bb0 <__fpclassifyl>:
   140008bb0:	55                   	push   rbp
   140008bb1:	53                   	push   rbx
   140008bb2:	48 83 ec 38          	sub    rsp,0x38
   140008bb6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008bbb:	48 89 cb             	mov    rbx,rcx
   140008bbe:	db 2b                	fld    TBYTE PTR [rbx]
   140008bc0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008bc3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008bc6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008bc9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008bcd:	98                   	cwde
   140008bce:	25 ff 7f 00 00       	and    eax,0x7fff
   140008bd3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008bd6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008bda:	75 25                	jne    140008c01 <__fpclassifyl+0x51>
   140008bdc:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008bdf:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008be2:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008be5:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008be8:	85 c0                	test   eax,eax
   140008bea:	75 07                	jne    140008bf3 <__fpclassifyl+0x43>
   140008bec:	b8 00 40 00 00       	mov    eax,0x4000
   140008bf1:	eb 3d                	jmp    140008c30 <__fpclassifyl+0x80>
   140008bf3:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008bf6:	85 c0                	test   eax,eax
   140008bf8:	78 31                	js     140008c2b <__fpclassifyl+0x7b>
   140008bfa:	b8 00 44 00 00       	mov    eax,0x4400
   140008bff:	eb 2f                	jmp    140008c30 <__fpclassifyl+0x80>
   140008c01:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008c08:	75 21                	jne    140008c2b <__fpclassifyl+0x7b>
   140008c0a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008c0d:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c12:	89 c2                	mov    edx,eax
   140008c14:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008c17:	09 d0                	or     eax,edx
   140008c19:	85 c0                	test   eax,eax
   140008c1b:	75 07                	jne    140008c24 <__fpclassifyl+0x74>
   140008c1d:	b8 00 05 00 00       	mov    eax,0x500
   140008c22:	eb 0c                	jmp    140008c30 <__fpclassifyl+0x80>
   140008c24:	b8 00 01 00 00       	mov    eax,0x100
   140008c29:	eb 05                	jmp    140008c30 <__fpclassifyl+0x80>
   140008c2b:	b8 00 04 00 00       	mov    eax,0x400
   140008c30:	48 83 c4 38          	add    rsp,0x38
   140008c34:	5b                   	pop    rbx
   140008c35:	5d                   	pop    rbp
   140008c36:	c3                   	ret
   140008c37:	90                   	nop
   140008c38:	90                   	nop
   140008c39:	90                   	nop
   140008c3a:	90                   	nop
   140008c3b:	90                   	nop
   140008c3c:	90                   	nop
   140008c3d:	90                   	nop
   140008c3e:	90                   	nop
   140008c3f:	90                   	nop

0000000140008c40 <__isnan>:
   140008c40:	55                   	push   rbp
   140008c41:	48 89 e5             	mov    rbp,rsp
   140008c44:	48 83 ec 10          	sub    rsp,0x10
   140008c48:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c4d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c52:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c57:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c5a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c5d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c60:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008c65:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c68:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c6b:	f7 d8                	neg    eax
   140008c6d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008c70:	c1 e8 1f             	shr    eax,0x1f
   140008c73:	89 c2                	mov    edx,eax
   140008c75:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c78:	09 d0                	or     eax,edx
   140008c7a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c7d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008c82:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008c85:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c88:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008c8b:	c1 f8 1f             	sar    eax,0x1f
   140008c8e:	48 83 c4 10          	add    rsp,0x10
   140008c92:	5d                   	pop    rbp
   140008c93:	c3                   	ret
   140008c94:	90                   	nop
   140008c95:	90                   	nop
   140008c96:	90                   	nop
   140008c97:	90                   	nop
   140008c98:	90                   	nop
   140008c99:	90                   	nop
   140008c9a:	90                   	nop
   140008c9b:	90                   	nop
   140008c9c:	90                   	nop
   140008c9d:	90                   	nop
   140008c9e:	90                   	nop
   140008c9f:	90                   	nop

0000000140008ca0 <__isnanl>:
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
   140008cbe:	01 c0                	add    eax,eax
   140008cc0:	25 ff ff 00 00       	and    eax,0xffff
   140008cc5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cc8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008ccb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008cce:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008cd4:	09 d0                	or     eax,edx
   140008cd6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cd9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008cdc:	f7 d8                	neg    eax
   140008cde:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008ce1:	c1 e8 1f             	shr    eax,0x1f
   140008ce4:	89 c2                	mov    edx,eax
   140008ce6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008ce9:	09 d0                	or     eax,edx
   140008ceb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cee:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008cf3:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008cf6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008cf9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008cfc:	c1 f8 10             	sar    eax,0x10
   140008cff:	48 83 c4 38          	add    rsp,0x38
   140008d03:	5b                   	pop    rbx
   140008d04:	5d                   	pop    rbp
   140008d05:	c3                   	ret
   140008d06:	90                   	nop
   140008d07:	90                   	nop
   140008d08:	90                   	nop
   140008d09:	90                   	nop
   140008d0a:	90                   	nop
   140008d0b:	90                   	nop
   140008d0c:	90                   	nop
   140008d0d:	90                   	nop
   140008d0e:	90                   	nop
   140008d0f:	90                   	nop

0000000140008d10 <wcsnlen>:
   140008d10:	55                   	push   rbp
   140008d11:	48 89 e5             	mov    rbp,rsp
   140008d14:	48 83 ec 10          	sub    rsp,0x10
   140008d18:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d1c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d20:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008d27:	00 
   140008d28:	eb 0a                	jmp    140008d34 <wcsnlen+0x24>
   140008d2a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d2f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008d34:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d38:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d3c:	73 0c                	jae    140008d4a <wcsnlen+0x3a>
   140008d3e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008d42:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008d45:	66 85 c0             	test   ax,ax
   140008d48:	75 e0                	jne    140008d2a <wcsnlen+0x1a>
   140008d4a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d4e:	48 83 c4 10          	add    rsp,0x10
   140008d52:	5d                   	pop    rbp
   140008d53:	c3                   	ret
   140008d54:	90                   	nop
   140008d55:	90                   	nop
   140008d56:	90                   	nop
   140008d57:	90                   	nop
   140008d58:	90                   	nop
   140008d59:	90                   	nop
   140008d5a:	90                   	nop
   140008d5b:	90                   	nop
   140008d5c:	90                   	nop
   140008d5d:	90                   	nop
   140008d5e:	90                   	nop
   140008d5f:	90                   	nop

0000000140008d60 <strnlen>:
   140008d60:	55                   	push   rbp
   140008d61:	48 89 e5             	mov    rbp,rsp
   140008d64:	48 83 ec 10          	sub    rsp,0x10
   140008d68:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008d6c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008d70:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008d74:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008d78:	eb 05                	jmp    140008d7f <strnlen+0x1f>
   140008d7a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008d7f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d83:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008d87:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008d8b:	73 0b                	jae    140008d98 <strnlen+0x38>
   140008d8d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d91:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008d94:	84 c0                	test   al,al
   140008d96:	75 e2                	jne    140008d7a <strnlen+0x1a>
   140008d98:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008d9c:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008da0:	48 83 c4 10          	add    rsp,0x10
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

0000000140008db0 <_initterm_e>:
   140008db0:	55                   	push   rbp
   140008db1:	48 89 e5             	mov    rbp,rsp
   140008db4:	48 83 ec 30          	sub    rsp,0x30
   140008db8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008dbc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008dc0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008dc4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008dc8:	eb 29                	jmp    140008df3 <_initterm_e+0x43>
   140008dca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dce:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008dd1:	48 85 c0             	test   rax,rax
   140008dd4:	74 17                	je     140008ded <_initterm_e+0x3d>
   140008dd6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008dda:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ddd:	ff d0                	call   rax
   140008ddf:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008de2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008de6:	74 06                	je     140008dee <_initterm_e+0x3e>
   140008de8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008deb:	eb 15                	jmp    140008e02 <_initterm_e+0x52>
   140008ded:	90                   	nop
   140008dee:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008df3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008df7:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008dfb:	72 cd                	jb     140008dca <_initterm_e+0x1a>
   140008dfd:	b8 00 00 00 00       	mov    eax,0x0
   140008e02:	48 83 c4 30          	add    rsp,0x30
   140008e06:	5d                   	pop    rbp
   140008e07:	c3                   	ret
   140008e08:	90                   	nop
   140008e09:	90                   	nop
   140008e0a:	90                   	nop
   140008e0b:	90                   	nop
   140008e0c:	90                   	nop
   140008e0d:	90                   	nop
   140008e0e:	90                   	nop
   140008e0f:	90                   	nop

0000000140008e10 <__p__fmode>:
   140008e10:	55                   	push   rbp
   140008e11:	48 89 e5             	mov    rbp,rsp
   140008e14:	48 8b 05 e5 27 00 00 	mov    rax,QWORD PTR [rip+0x27e5]        # 14000b600 <.refptr.__imp__fmode>
   140008e1b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e1e:	5d                   	pop    rbp
   140008e1f:	c3                   	ret

0000000140008e20 <__p__commode>:
   140008e20:	55                   	push   rbp
   140008e21:	48 89 e5             	mov    rbp,rsp
   140008e24:	48 8b 05 c5 27 00 00 	mov    rax,QWORD PTR [rip+0x27c5]        # 14000b5f0 <.refptr.__imp__commode>
   140008e2b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e2e:	5d                   	pop    rbp
   140008e2f:	c3                   	ret

0000000140008e30 <__p___initenv>:
   140008e30:	55                   	push   rbp
   140008e31:	48 89 e5             	mov    rbp,rsp
   140008e34:	48 8b 05 a5 27 00 00 	mov    rax,QWORD PTR [rip+0x27a5]        # 14000b5e0 <.refptr.__imp___initenv>
   140008e3b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008e3e:	5d                   	pop    rbp
   140008e3f:	c3                   	ret

0000000140008e40 <_lock_file>:
   140008e40:	55                   	push   rbp
   140008e41:	48 89 e5             	mov    rbp,rsp
   140008e44:	48 83 ec 20          	sub    rsp,0x20
   140008e48:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e4c:	b9 00 00 00 00       	mov    ecx,0x0
   140008e51:	e8 6a 01 00 00       	call   140008fc0 <__acrt_iob_func>
   140008e56:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008e5a:	72 52                	jb     140008eae <_lock_file+0x6e>
   140008e5c:	b9 13 00 00 00       	mov    ecx,0x13
   140008e61:	e8 5a 01 00 00       	call   140008fc0 <__acrt_iob_func>
   140008e66:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008e6a:	72 42                	jb     140008eae <_lock_file+0x6e>
   140008e6c:	b9 00 00 00 00       	mov    ecx,0x0
   140008e71:	e8 4a 01 00 00       	call   140008fc0 <__acrt_iob_func>
   140008e76:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008e7a:	48 29 c2             	sub    rdx,rax
   140008e7d:	48 c1 fa 04          	sar    rdx,0x4
   140008e81:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008e88:	aa aa aa 
   140008e8b:	48 0f af c2          	imul   rax,rdx
   140008e8f:	83 c0 10             	add    eax,0x10
   140008e92:	89 c1                	mov    ecx,eax
   140008e94:	e8 1f 07 00 00       	call   1400095b8 <_lock>
   140008e99:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e9d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008ea0:	80 cc 80             	or     ah,0x80
   140008ea3:	89 c2                	mov    edx,eax
   140008ea5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ea9:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008eac:	eb 15                	jmp    140008ec3 <_lock_file+0x83>
   140008eae:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008eb2:	48 83 c0 30          	add    rax,0x30
   140008eb6:	48 89 c1             	mov    rcx,rax
   140008eb9:	48 8b 05 38 73 00 00 	mov    rax,QWORD PTR [rip+0x7338]        # 1400101f8 <__imp_EnterCriticalSection>
   140008ec0:	ff d0                	call   rax
   140008ec2:	90                   	nop
   140008ec3:	90                   	nop
   140008ec4:	48 83 c4 20          	add    rsp,0x20
   140008ec8:	5d                   	pop    rbp
   140008ec9:	c3                   	ret

0000000140008eca <_unlock_file>:
   140008eca:	55                   	push   rbp
   140008ecb:	48 89 e5             	mov    rbp,rsp
   140008ece:	48 83 ec 20          	sub    rsp,0x20
   140008ed2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ed6:	b9 00 00 00 00       	mov    ecx,0x0
   140008edb:	e8 e0 00 00 00       	call   140008fc0 <__acrt_iob_func>
   140008ee0:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008ee4:	72 52                	jb     140008f38 <_unlock_file+0x6e>
   140008ee6:	b9 13 00 00 00       	mov    ecx,0x13
   140008eeb:	e8 d0 00 00 00       	call   140008fc0 <__acrt_iob_func>
   140008ef0:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008ef4:	72 42                	jb     140008f38 <_unlock_file+0x6e>
   140008ef6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008efa:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008efd:	80 e4 7f             	and    ah,0x7f
   140008f00:	89 c2                	mov    edx,eax
   140008f02:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f06:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008f09:	b9 00 00 00 00       	mov    ecx,0x0
   140008f0e:	e8 ad 00 00 00       	call   140008fc0 <__acrt_iob_func>
   140008f13:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f17:	48 29 c2             	sub    rdx,rax
   140008f1a:	48 c1 fa 04          	sar    rdx,0x4
   140008f1e:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f25:	aa aa aa 
   140008f28:	48 0f af c2          	imul   rax,rdx
   140008f2c:	83 c0 10             	add    eax,0x10
   140008f2f:	89 c1                	mov    ecx,eax
   140008f31:	e8 8a 06 00 00       	call   1400095c0 <_unlock>
   140008f36:	eb 15                	jmp    140008f4d <_unlock_file+0x83>
   140008f38:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f3c:	48 83 c0 30          	add    rax,0x30
   140008f40:	48 89 c1             	mov    rcx,rax
   140008f43:	48 8b 05 e6 72 00 00 	mov    rax,QWORD PTR [rip+0x72e6]        # 140010230 <__imp_LeaveCriticalSection>
   140008f4a:	ff d0                	call   rax
   140008f4c:	90                   	nop
   140008f4d:	90                   	nop
   140008f4e:	48 83 c4 20          	add    rsp,0x20
   140008f52:	5d                   	pop    rbp
   140008f53:	c3                   	ret
   140008f54:	90                   	nop
   140008f55:	90                   	nop
   140008f56:	90                   	nop
   140008f57:	90                   	nop
   140008f58:	90                   	nop
   140008f59:	90                   	nop
   140008f5a:	90                   	nop
   140008f5b:	90                   	nop
   140008f5c:	90                   	nop
   140008f5d:	90                   	nop
   140008f5e:	90                   	nop
   140008f5f:	90                   	nop

0000000140008f60 <_set_invalid_parameter_handler>:
   140008f60:	55                   	push   rbp
   140008f61:	48 89 e5             	mov    rbp,rsp
   140008f64:	48 83 ec 10          	sub    rsp,0x10
   140008f68:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f6c:	48 8d 05 0d 6c 00 00 	lea    rax,[rip+0x6c0d]        # 14000fb80 <handler>
   140008f73:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008f77:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008f7b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008f7f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140008f83:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008f87:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140008f8a:	48 89 d0             	mov    rax,rdx
   140008f8d:	48 83 c4 10          	add    rsp,0x10
   140008f91:	5d                   	pop    rbp
   140008f92:	c3                   	ret

0000000140008f93 <_get_invalid_parameter_handler>:
   140008f93:	55                   	push   rbp
   140008f94:	48 89 e5             	mov    rbp,rsp
   140008f97:	48 8b 05 e2 6b 00 00 	mov    rax,QWORD PTR [rip+0x6be2]        # 14000fb80 <handler>
   140008f9e:	5d                   	pop    rbp
   140008f9f:	c3                   	ret

0000000140008fa0 <_configthreadlocale>:
   140008fa0:	55                   	push   rbp
   140008fa1:	48 89 e5             	mov    rbp,rsp
   140008fa4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008fa7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   140008fab:	75 07                	jne    140008fb4 <_configthreadlocale+0x14>
   140008fad:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140008fb2:	eb 05                	jmp    140008fb9 <_configthreadlocale+0x19>
   140008fb4:	b8 02 00 00 00       	mov    eax,0x2
   140008fb9:	5d                   	pop    rbp
   140008fba:	c3                   	ret
   140008fbb:	90                   	nop
   140008fbc:	90                   	nop
   140008fbd:	90                   	nop
   140008fbe:	90                   	nop
   140008fbf:	90                   	nop

0000000140008fc0 <__acrt_iob_func>:
   140008fc0:	55                   	push   rbp
   140008fc1:	48 89 e5             	mov    rbp,rsp
   140008fc4:	48 83 ec 20          	sub    rsp,0x20
   140008fc8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008fcb:	e8 b0 05 00 00       	call   140009580 <__iob_func>
   140008fd0:	48 89 c1             	mov    rcx,rax
   140008fd3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008fd6:	48 89 d0             	mov    rax,rdx
   140008fd9:	48 01 c0             	add    rax,rax
   140008fdc:	48 01 d0             	add    rax,rdx
   140008fdf:	48 c1 e0 04          	shl    rax,0x4
   140008fe3:	48 01 c8             	add    rax,rcx
   140008fe6:	48 83 c4 20          	add    rsp,0x20
   140008fea:	5d                   	pop    rbp
   140008feb:	c3                   	ret
   140008fec:	90                   	nop
   140008fed:	90                   	nop
   140008fee:	90                   	nop
   140008fef:	90                   	nop

0000000140008ff0 <wcrtomb>:
   140008ff0:	55                   	push   rbp
   140008ff1:	48 89 e5             	mov    rbp,rsp
   140008ff4:	48 83 ec 40          	sub    rsp,0x40
   140008ff8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ffc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009000:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009004:	e8 5f 05 00 00       	call   140009568 <___lc_codepage_func>
   140009009:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000900c:	e8 5f 05 00 00       	call   140009570 <___mb_cur_max_func>
   140009011:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140009014:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140009018:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   14000901c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009020:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009024:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009027:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000902b:	48 89 c1             	mov    rcx,rax
   14000902e:	e8 7d 00 00 00       	call   1400090b0 <__mingw_wcrtomb_cp>
   140009033:	48 83 c4 40          	add    rsp,0x40
   140009037:	5d                   	pop    rbp
   140009038:	c3                   	ret
   140009039:	90                   	nop
   14000903a:	90                   	nop
   14000903b:	90                   	nop
   14000903c:	90                   	nop
   14000903d:	90                   	nop
   14000903e:	90                   	nop
   14000903f:	90                   	nop

0000000140009040 <mbrtowc>:
   140009040:	55                   	push   rbp
   140009041:	48 89 e5             	mov    rbp,rsp
   140009044:	48 83 ec 40          	sub    rsp,0x40
   140009048:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000904c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009050:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009054:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009058:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000905d:	75 0b                	jne    14000906a <mbrtowc+0x2a>
   14000905f:	48 8d 05 2a 6b 00 00 	lea    rax,[rip+0x6b2a]        # 14000fb90 <state_mbrtowc.0>
   140009066:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000906a:	e8 f9 04 00 00       	call   140009568 <___lc_codepage_func>
   14000906f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009072:	e8 f9 04 00 00       	call   140009570 <___mb_cur_max_func>
   140009077:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000907a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000907e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009082:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009086:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000908a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000908d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   140009091:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   140009094:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   140009098:	48 89 c1             	mov    rcx,rax
   14000909b:	e8 70 01 00 00       	call   140009210 <__mingw_mbrtowc_cp>
   1400090a0:	48 83 c4 40          	add    rsp,0x40
   1400090a4:	5d                   	pop    rbp
   1400090a5:	c3                   	ret
   1400090a6:	90                   	nop
   1400090a7:	90                   	nop
   1400090a8:	90                   	nop
   1400090a9:	90                   	nop
   1400090aa:	90                   	nop
   1400090ab:	90                   	nop
   1400090ac:	90                   	nop
   1400090ad:	90                   	nop
   1400090ae:	90                   	nop
   1400090af:	90                   	nop

00000001400090b0 <__mingw_wcrtomb_cp>:
   1400090b0:	55                   	push   rbp
   1400090b1:	48 89 e5             	mov    rbp,rsp
   1400090b4:	48 83 ec 50          	sub    rsp,0x50
   1400090b8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400090bc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400090c0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400090c4:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   1400090c8:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400090cd:	75 1b                	jne    1400090ea <__mingw_wcrtomb_cp+0x3a>
   1400090cf:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400090d4:	74 0a                	je     1400090e0 <__mingw_wcrtomb_cp+0x30>
   1400090d6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400090da:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400090e0:	b8 01 00 00 00       	mov    eax,0x1
   1400090e5:	e9 17 01 00 00       	jmp    140009201 <__mingw_wcrtomb_cp+0x151>
   1400090ea:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400090ef:	74 21                	je     140009112 <__mingw_wcrtomb_cp+0x62>
   1400090f1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400090f5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400090f7:	85 c0                	test   eax,eax
   1400090f9:	74 17                	je     140009112 <__mingw_wcrtomb_cp+0x62>
   1400090fb:	e8 a8 04 00 00       	call   1400095a8 <_errno>
   140009100:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009106:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000910d:	e9 ef 00 00 00       	jmp    140009201 <__mingw_wcrtomb_cp+0x151>
   140009112:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009116:	66 85 c0             	test   ax,ax
   140009119:	75 18                	jne    140009133 <__mingw_wcrtomb_cp+0x83>
   14000911b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009120:	74 07                	je     140009129 <__mingw_wcrtomb_cp+0x79>
   140009122:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009126:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009129:	b8 01 00 00 00       	mov    eax,0x1
   14000912e:	e9 ce 00 00 00       	jmp    140009201 <__mingw_wcrtomb_cp+0x151>
   140009133:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009137:	75 2b                	jne    140009164 <__mingw_wcrtomb_cp+0xb4>
   140009139:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000913d:	66 3d ff 00          	cmp    ax,0xff
   140009141:	0f 87 a4 00 00 00    	ja     1400091eb <__mingw_wcrtomb_cp+0x13b>
   140009147:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000914c:	74 0c                	je     14000915a <__mingw_wcrtomb_cp+0xaa>
   14000914e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009152:	89 c2                	mov    edx,eax
   140009154:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009158:	88 10                	mov    BYTE PTR [rax],dl
   14000915a:	b8 01 00 00 00       	mov    eax,0x1
   14000915f:	e9 9d 00 00 00       	jmp    140009201 <__mingw_wcrtomb_cp+0x151>
   140009164:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000916b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009171:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009175:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009178:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000917c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009181:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009188:	00 00 
   14000918a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000918d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140009191:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   140009195:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   14000919a:	41 b9 01 00 00 00    	mov    r9d,0x1
   1400091a0:	49 89 c8             	mov    r8,rcx
   1400091a3:	ba 00 00 00 00       	mov    edx,0x0
   1400091a8:	89 c1                	mov    ecx,eax
   1400091aa:	48 8b 05 bf 70 00 00 	mov    rax,QWORD PTR [rip+0x70bf]        # 140010270 <__imp_WideCharToMultiByte>
   1400091b1:	ff d0                	call   rax
   1400091b3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400091b6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400091ba:	74 32                	je     1400091ee <__mingw_wcrtomb_cp+0x13e>
   1400091bc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091bf:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   1400091c2:	7f 2a                	jg     1400091ee <__mingw_wcrtomb_cp+0x13e>
   1400091c4:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400091c7:	85 c0                	test   eax,eax
   1400091c9:	75 23                	jne    1400091ee <__mingw_wcrtomb_cp+0x13e>
   1400091cb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091ce:	48 63 c8             	movsxd rcx,eax
   1400091d1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400091d5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400091d9:	49 89 c8             	mov    r8,rcx
   1400091dc:	48 89 c1             	mov    rcx,rax
   1400091df:	e8 3c 04 00 00       	call   140009620 <memcpy>
   1400091e4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400091e7:	48 98                	cdqe
   1400091e9:	eb 16                	jmp    140009201 <__mingw_wcrtomb_cp+0x151>
   1400091eb:	90                   	nop
   1400091ec:	eb 01                	jmp    1400091ef <__mingw_wcrtomb_cp+0x13f>
   1400091ee:	90                   	nop
   1400091ef:	e8 b4 03 00 00       	call   1400095a8 <_errno>
   1400091f4:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   1400091fa:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009201:	48 83 c4 50          	add    rsp,0x50
   140009205:	5d                   	pop    rbp
   140009206:	c3                   	ret
   140009207:	90                   	nop
   140009208:	90                   	nop
   140009209:	90                   	nop
   14000920a:	90                   	nop
   14000920b:	90                   	nop
   14000920c:	90                   	nop
   14000920d:	90                   	nop
   14000920e:	90                   	nop
   14000920f:	90                   	nop

0000000140009210 <__mingw_mbrtowc_cp>:
   140009210:	55                   	push   rbp
   140009211:	48 89 e5             	mov    rbp,rsp
   140009214:	48 83 ec 50          	sub    rsp,0x50
   140009218:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000921c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009220:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009224:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009228:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000922d:	75 1b                	jne    14000924a <__mingw_mbrtowc_cp+0x3a>
   14000922f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009236:	00 
   140009237:	48 8d 05 e2 22 00 00 	lea    rax,[rip+0x22e2]        # 14000b520 <.rdata>
   14000923e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009242:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009249:	00 
   14000924a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000924e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009250:	3d ff 00 00 00       	cmp    eax,0xff
   140009255:	0f 87 b9 01 00 00    	ja     140009414 <__mingw_mbrtowc_cp+0x204>
   14000925b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009260:	75 0c                	jne    14000926e <__mingw_mbrtowc_cp+0x5e>
   140009262:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009269:	e9 bc 01 00 00       	jmp    14000942a <__mingw_mbrtowc_cp+0x21a>
   14000926e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009272:	8b 00                	mov    eax,DWORD PTR [rax]
   140009274:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009277:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000927b:	75 0c                	jne    140009289 <__mingw_mbrtowc_cp+0x79>
   14000927d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009281:	84 c0                	test   al,al
   140009283:	0f 85 8e 01 00 00    	jne    140009417 <__mingw_mbrtowc_cp+0x207>
   140009289:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000928d:	75 2c                	jne    1400092bb <__mingw_mbrtowc_cp+0xab>
   14000928f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009294:	74 11                	je     1400092a7 <__mingw_mbrtowc_cp+0x97>
   140009296:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000929a:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000929d:	0f b6 d0             	movzx  edx,al
   1400092a0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092a4:	66 89 10             	mov    WORD PTR [rax],dx
   1400092a7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092ab:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092ae:	84 c0                	test   al,al
   1400092b0:	0f 95 c0             	setne  al
   1400092b3:	0f b6 c0             	movzx  eax,al
   1400092b6:	e9 6f 01 00 00       	jmp    14000942a <__mingw_mbrtowc_cp+0x21a>
   1400092bb:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400092c2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400092c9:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400092cd:	84 c0                	test   al,al
   1400092cf:	74 1a                	je     1400092eb <__mingw_mbrtowc_cp+0xdb>
   1400092d1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092d5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092d8:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400092db:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400092e2:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400092e9:	eb 73                	jmp    14000935e <__mingw_mbrtowc_cp+0x14e>
   1400092eb:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   1400092ef:	75 5c                	jne    14000934d <__mingw_mbrtowc_cp+0x13d>
   1400092f1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400092f5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400092f8:	0f b6 c0             	movzx  eax,al
   1400092fb:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   1400092fe:	89 c1                	mov    ecx,eax
   140009300:	e8 ab 01 00 00       	call   1400094b0 <__mingw_isleadbyte_cp>
   140009305:	85 c0                	test   eax,eax
   140009307:	74 44                	je     14000934d <__mingw_mbrtowc_cp+0x13d>
   140009309:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000930d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009310:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009313:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009318:	77 15                	ja     14000932f <__mingw_mbrtowc_cp+0x11f>
   14000931a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000931d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009321:	89 10                	mov    DWORD PTR [rax],edx
   140009323:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000932a:	e9 fb 00 00 00       	jmp    14000942a <__mingw_mbrtowc_cp+0x21a>
   14000932f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009333:	48 83 c0 01          	add    rax,0x1
   140009337:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000933a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000933d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009344:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000934b:	eb 11                	jmp    14000935e <__mingw_mbrtowc_cp+0x14e>
   14000934d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009351:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009354:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009357:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000935e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009362:	84 c0                	test   al,al
   140009364:	75 24                	jne    14000938a <__mingw_mbrtowc_cp+0x17a>
   140009366:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000936b:	74 09                	je     140009376 <__mingw_mbrtowc_cp+0x166>
   14000936d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009371:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009376:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000937a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009380:	b8 00 00 00 00       	mov    eax,0x0
   140009385:	e9 a0 00 00 00       	jmp    14000942a <__mingw_mbrtowc_cp+0x21a>
   14000938a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000938e:	75 08                	jne    140009398 <__mingw_mbrtowc_cp+0x188>
   140009390:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   140009394:	84 c0                	test   al,al
   140009396:	74 64                	je     1400093fc <__mingw_mbrtowc_cp+0x1ec>
   140009398:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   14000939e:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   1400093a2:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400093a6:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   1400093a9:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   1400093b0:	00 
   1400093b1:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   1400093b5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400093ba:	45 89 c1             	mov    r9d,r8d
   1400093bd:	49 89 c8             	mov    r8,rcx
   1400093c0:	ba 08 00 00 00       	mov    edx,0x8
   1400093c5:	89 c1                	mov    ecx,eax
   1400093c7:	48 8b 05 72 6e 00 00 	mov    rax,QWORD PTR [rip+0x6e72]        # 140010240 <__imp_MultiByteToWideChar>
   1400093ce:	ff d0                	call   rax
   1400093d0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400093d3:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   1400093d7:	75 26                	jne    1400093ff <__mingw_mbrtowc_cp+0x1ef>
   1400093d9:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400093de:	74 0b                	je     1400093eb <__mingw_mbrtowc_cp+0x1db>
   1400093e0:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   1400093e4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400093e8:	66 89 10             	mov    WORD PTR [rax],dx
   1400093eb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400093ef:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400093f5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400093f8:	48 98                	cdqe
   1400093fa:	eb 2e                	jmp    14000942a <__mingw_mbrtowc_cp+0x21a>
   1400093fc:	90                   	nop
   1400093fd:	eb 01                	jmp    140009400 <__mingw_mbrtowc_cp+0x1f0>
   1400093ff:	90                   	nop
   140009400:	e8 a3 01 00 00       	call   1400095a8 <_errno>
   140009405:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000940b:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009412:	eb 16                	jmp    14000942a <__mingw_mbrtowc_cp+0x21a>
   140009414:	90                   	nop
   140009415:	eb 01                	jmp    140009418 <__mingw_mbrtowc_cp+0x208>
   140009417:	90                   	nop
   140009418:	e8 8b 01 00 00       	call   1400095a8 <_errno>
   14000941d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009423:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000942a:	48 83 c4 50          	add    rsp,0x50
   14000942e:	5d                   	pop    rbp
   14000942f:	c3                   	ret

0000000140009430 <fallback_IsDBCSLeadByteEx>:
   140009430:	55                   	push   rbp
   140009431:	48 89 e5             	mov    rbp,rsp
   140009434:	48 83 ec 40          	sub    rsp,0x40
   140009438:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000943b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000943e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009442:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009445:	89 c1                	mov    ecx,eax
   140009447:	48 8b 05 ba 6d 00 00 	mov    rax,QWORD PTR [rip+0x6dba]        # 140010208 <__imp_GetCPInfo>
   14000944e:	ff d0                	call   rax
   140009450:	85 c0                	test   eax,eax
   140009452:	74 51                	je     1400094a5 <fallback_IsDBCSLeadByteEx+0x75>
   140009454:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009457:	83 f8 02             	cmp    eax,0x2
   14000945a:	75 49                	jne    1400094a5 <fallback_IsDBCSLeadByteEx+0x75>
   14000945c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009463:	eb 2c                	jmp    140009491 <fallback_IsDBCSLeadByteEx+0x61>
   140009465:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009468:	48 98                	cdqe
   14000946a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000946f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009472:	72 19                	jb     14000948d <fallback_IsDBCSLeadByteEx+0x5d>
   140009474:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009477:	83 c0 01             	add    eax,0x1
   14000947a:	48 98                	cdqe
   14000947c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009481:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009484:	72 07                	jb     14000948d <fallback_IsDBCSLeadByteEx+0x5d>
   140009486:	b8 01 00 00 00       	mov    eax,0x1
   14000948b:	eb 1d                	jmp    1400094aa <fallback_IsDBCSLeadByteEx+0x7a>
   14000948d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   140009491:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   140009495:	7f 0e                	jg     1400094a5 <fallback_IsDBCSLeadByteEx+0x75>
   140009497:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000949a:	48 98                	cdqe
   14000949c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400094a1:	84 c0                	test   al,al
   1400094a3:	75 c0                	jne    140009465 <fallback_IsDBCSLeadByteEx+0x35>
   1400094a5:	b8 00 00 00 00       	mov    eax,0x0
   1400094aa:	48 83 c4 40          	add    rsp,0x40
   1400094ae:	5d                   	pop    rbp
   1400094af:	c3                   	ret

00000001400094b0 <__mingw_isleadbyte_cp>:
   1400094b0:	55                   	push   rbp
   1400094b1:	48 89 e5             	mov    rbp,rsp
   1400094b4:	48 83 ec 40          	sub    rsp,0x40
   1400094b8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400094bb:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400094be:	48 8b 05 db 66 00 00 	mov    rax,QWORD PTR [rip+0x66db]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400094c5:	48 85 c0             	test   rax,rax
   1400094c8:	75 71                	jne    14000953b <__mingw_isleadbyte_cp+0x8b>
   1400094ca:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400094d1:	00 
   1400094d2:	48 8d 05 57 20 00 00 	lea    rax,[rip+0x2057]        # 14000b530 <.rdata>
   1400094d9:	48 89 c1             	mov    rcx,rax
   1400094dc:	48 8b 05 35 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d35]        # 140010218 <__imp_GetModuleHandleA>
   1400094e3:	ff d0                	call   rax
   1400094e5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400094e9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400094ee:	74 1b                	je     14000950b <__mingw_isleadbyte_cp+0x5b>
   1400094f0:	48 8d 15 46 20 00 00 	lea    rdx,[rip+0x2046]        # 14000b53d <.rdata+0xd>
   1400094f7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400094fb:	48 89 c1             	mov    rcx,rax
   1400094fe:	48 8b 05 1b 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d1b]        # 140010220 <__imp_GetProcAddress>
   140009505:	ff d0                	call   rax
   140009507:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000950b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009510:	75 0b                	jne    14000951d <__mingw_isleadbyte_cp+0x6d>
   140009512:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009430 <fallback_IsDBCSLeadByteEx>
   140009519:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000951d:	48 8d 05 7c 66 00 00 	lea    rax,[rip+0x667c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009524:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009528:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000952c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009530:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009534:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009538:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000953b:	4c 8b 05 5e 66 00 00 	mov    r8,QWORD PTR [rip+0x665e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009542:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009545:	0f b6 d0             	movzx  edx,al
   140009548:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000954b:	89 c1                	mov    ecx,eax
   14000954d:	41 ff d0             	call   r8
   140009550:	48 83 c4 40          	add    rsp,0x40
   140009554:	5d                   	pop    rbp
   140009555:	c3                   	ret
   140009556:	90                   	nop
   140009557:	90                   	nop
   140009558:	90                   	nop
   140009559:	90                   	nop
   14000955a:	90                   	nop
   14000955b:	90                   	nop
   14000955c:	90                   	nop
   14000955d:	90                   	nop
   14000955e:	90                   	nop
   14000955f:	90                   	nop

0000000140009560 <__C_specific_handler>:
   140009560:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010280 <__imp___C_specific_handler>
   140009566:	90                   	nop
   140009567:	90                   	nop

0000000140009568 <___lc_codepage_func>:
   140009568:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010288 <__imp____lc_codepage_func>
   14000956e:	90                   	nop
   14000956f:	90                   	nop

0000000140009570 <___mb_cur_max_func>:
   140009570:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010290 <__imp____mb_cur_max_func>
   140009576:	90                   	nop
   140009577:	90                   	nop

0000000140009578 <__getmainargs>:
   140009578:	ff 25 1a 6d 00 00    	jmp    QWORD PTR [rip+0x6d1a]        # 140010298 <__imp___getmainargs>
   14000957e:	90                   	nop
   14000957f:	90                   	nop

0000000140009580 <__iob_func>:
   140009580:	ff 25 22 6d 00 00    	jmp    QWORD PTR [rip+0x6d22]        # 1400102a8 <__imp___iob_func>
   140009586:	90                   	nop
   140009587:	90                   	nop

0000000140009588 <__set_app_type>:
   140009588:	ff 25 22 6d 00 00    	jmp    QWORD PTR [rip+0x6d22]        # 1400102b0 <__imp___set_app_type>
   14000958e:	90                   	nop
   14000958f:	90                   	nop

0000000140009590 <__setusermatherr>:
   140009590:	ff 25 22 6d 00 00    	jmp    QWORD PTR [rip+0x6d22]        # 1400102b8 <__imp___setusermatherr>
   140009596:	90                   	nop
   140009597:	90                   	nop

0000000140009598 <_amsg_exit>:
   140009598:	ff 25 22 6d 00 00    	jmp    QWORD PTR [rip+0x6d22]        # 1400102c0 <__imp__amsg_exit>
   14000959e:	90                   	nop
   14000959f:	90                   	nop

00000001400095a0 <_cexit>:
   1400095a0:	ff 25 22 6d 00 00    	jmp    QWORD PTR [rip+0x6d22]        # 1400102c8 <__imp__cexit>
   1400095a6:	90                   	nop
   1400095a7:	90                   	nop

00000001400095a8 <_errno>:
   1400095a8:	ff 25 2a 6d 00 00    	jmp    QWORD PTR [rip+0x6d2a]        # 1400102d8 <__imp__errno>
   1400095ae:	90                   	nop
   1400095af:	90                   	nop

00000001400095b0 <_initterm>:
   1400095b0:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 1400102e8 <__imp__initterm>
   1400095b6:	90                   	nop
   1400095b7:	90                   	nop

00000001400095b8 <_lock>:
   1400095b8:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 1400102f0 <__imp__lock>
   1400095be:	90                   	nop
   1400095bf:	90                   	nop

00000001400095c0 <_unlock>:
   1400095c0:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 1400102f8 <__imp__unlock>
   1400095c6:	90                   	nop
   1400095c7:	90                   	nop

00000001400095c8 <_crt_atexit>:
   1400095c8:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010300 <__imp__crt_atexit>
   1400095ce:	90                   	nop
   1400095cf:	90                   	nop

00000001400095d0 <abort>:
   1400095d0:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010308 <__imp_abort>
   1400095d6:	90                   	nop
   1400095d7:	90                   	nop

00000001400095d8 <calloc>:
   1400095d8:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010310 <__imp_calloc>
   1400095de:	90                   	nop
   1400095df:	90                   	nop

00000001400095e0 <exit>:
   1400095e0:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010318 <__imp_exit>
   1400095e6:	90                   	nop
   1400095e7:	90                   	nop

00000001400095e8 <fflush>:
   1400095e8:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010320 <__imp_fflush>
   1400095ee:	90                   	nop
   1400095ef:	90                   	nop

00000001400095f0 <fgets>:
   1400095f0:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010328 <__imp_fgets>
   1400095f6:	90                   	nop
   1400095f7:	90                   	nop

00000001400095f8 <fprintf>:
   1400095f8:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010330 <__imp_fprintf>
   1400095fe:	90                   	nop
   1400095ff:	90                   	nop

0000000140009600 <fputc>:
   140009600:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010338 <__imp_fputc>
   140009606:	90                   	nop
   140009607:	90                   	nop

0000000140009608 <free>:
   140009608:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010340 <__imp_free>
   14000960e:	90                   	nop
   14000960f:	90                   	nop

0000000140009610 <localeconv>:
   140009610:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010348 <__imp_localeconv>
   140009616:	90                   	nop
   140009617:	90                   	nop

0000000140009618 <malloc>:
   140009618:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010350 <__imp_malloc>
   14000961e:	90                   	nop
   14000961f:	90                   	nop

0000000140009620 <memcpy>:
   140009620:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010358 <__imp_memcpy>
   140009626:	90                   	nop
   140009627:	90                   	nop

0000000140009628 <setvbuf>:
   140009628:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010360 <__imp_setvbuf>
   14000962e:	90                   	nop
   14000962f:	90                   	nop

0000000140009630 <signal>:
   140009630:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010368 <__imp_signal>
   140009636:	90                   	nop
   140009637:	90                   	nop

0000000140009638 <strerror>:
   140009638:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010370 <__imp_strerror>
   14000963e:	90                   	nop
   14000963f:	90                   	nop

0000000140009640 <strlen>:
   140009640:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010378 <__imp_strlen>
   140009646:	90                   	nop
   140009647:	90                   	nop

0000000140009648 <strncmp>:
   140009648:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010380 <__imp_strncmp>
   14000964e:	90                   	nop
   14000964f:	90                   	nop

0000000140009650 <vfprintf>:
   140009650:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010388 <__imp_vfprintf>
   140009656:	90                   	nop
   140009657:	90                   	nop

0000000140009658 <wcslen>:
   140009658:	ff 25 32 6d 00 00    	jmp    QWORD PTR [rip+0x6d32]        # 140010390 <__imp_wcslen>
   14000965e:	90                   	nop
   14000965f:	90                   	nop

0000000140009660 <WideCharToMultiByte>:
   140009660:	ff 25 0a 6c 00 00    	jmp    QWORD PTR [rip+0x6c0a]        # 140010270 <__imp_WideCharToMultiByte>
   140009666:	90                   	nop
   140009667:	90                   	nop

0000000140009668 <VirtualQuery>:
   140009668:	ff 25 fa 6b 00 00    	jmp    QWORD PTR [rip+0x6bfa]        # 140010268 <__imp_VirtualQuery>
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <VirtualProtect>:
   140009670:	ff 25 ea 6b 00 00    	jmp    QWORD PTR [rip+0x6bea]        # 140010260 <__imp_VirtualProtect>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <TlsGetValue>:
   140009678:	ff 25 da 6b 00 00    	jmp    QWORD PTR [rip+0x6bda]        # 140010258 <__imp_TlsGetValue>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <Sleep>:
   140009680:	ff 25 ca 6b 00 00    	jmp    QWORD PTR [rip+0x6bca]        # 140010250 <__imp_Sleep>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <SetUnhandledExceptionFilter>:
   140009688:	ff 25 ba 6b 00 00    	jmp    QWORD PTR [rip+0x6bba]        # 140010248 <__imp_SetUnhandledExceptionFilter>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <MultiByteToWideChar>:
   140009690:	ff 25 aa 6b 00 00    	jmp    QWORD PTR [rip+0x6baa]        # 140010240 <__imp_MultiByteToWideChar>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <LoadLibraryA>:
   140009698:	ff 25 9a 6b 00 00    	jmp    QWORD PTR [rip+0x6b9a]        # 140010238 <__imp_LoadLibraryA>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <LeaveCriticalSection>:
   1400096a0:	ff 25 8a 6b 00 00    	jmp    QWORD PTR [rip+0x6b8a]        # 140010230 <__imp_LeaveCriticalSection>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <InitializeCriticalSection>:
   1400096a8:	ff 25 7a 6b 00 00    	jmp    QWORD PTR [rip+0x6b7a]        # 140010228 <__imp_InitializeCriticalSection>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <GetProcAddress>:
   1400096b0:	ff 25 6a 6b 00 00    	jmp    QWORD PTR [rip+0x6b6a]        # 140010220 <__imp_GetProcAddress>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <GetModuleHandleA>:
   1400096b8:	ff 25 5a 6b 00 00    	jmp    QWORD PTR [rip+0x6b5a]        # 140010218 <__imp_GetModuleHandleA>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <GetLastError>:
   1400096c0:	ff 25 4a 6b 00 00    	jmp    QWORD PTR [rip+0x6b4a]        # 140010210 <__imp_GetLastError>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <GetCPInfo>:
   1400096c8:	ff 25 3a 6b 00 00    	jmp    QWORD PTR [rip+0x6b3a]        # 140010208 <__imp_GetCPInfo>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <FreeLibrary>:
   1400096d0:	ff 25 2a 6b 00 00    	jmp    QWORD PTR [rip+0x6b2a]        # 140010200 <__imp_FreeLibrary>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <EnterCriticalSection>:
   1400096d8:	ff 25 1a 6b 00 00    	jmp    QWORD PTR [rip+0x6b1a]        # 1400101f8 <__imp_EnterCriticalSection>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <DeleteCriticalSection>:
   1400096e0:	ff 25 0a 6b 00 00    	jmp    QWORD PTR [rip+0x6b0a]        # 1400101f0 <__IAT_start__>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop
   1400096e8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   1400096ef:	00 

00000001400096f0 <register_frame_ctor>:
   1400096f0:	e9 7b 7f ff ff       	jmp    140001670 <__gcc_register_frame>
   1400096f5:	90                   	nop
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop
   1400096f8:	90                   	nop
   1400096f9:	90                   	nop
   1400096fa:	90                   	nop
   1400096fb:	90                   	nop
   1400096fc:	90                   	nop
   1400096fd:	90                   	nop
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop
