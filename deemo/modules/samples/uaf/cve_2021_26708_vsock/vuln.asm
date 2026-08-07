
C:\Users\Administrator\Desktop\BinMind\round2\samples\uaf\cve_2021_26708_vsock\vuln.exe:     file format pei-x86-64


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
   140001024:	e8 cf 86 00 00       	call   1400096f8 <fflush>
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
   14000103f:	48 8b 05 ea a5 00 00 	mov    rax,QWORD PTR [rip+0xa5ea]        # 14000b630 <.refptr.__mingw_app_type>
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
   14000106e:	48 8b 05 bb a5 00 00 	mov    rax,QWORD PTR [rip+0xa5bb]        # 14000b630 <.refptr.__mingw_app_type>
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
   1400010e8:	48 8b 05 69 f1 00 00 	mov    rax,QWORD PTR [rip+0xf169]        # 140010258 <__imp_Sleep>
   1400010ef:	ff d0                	call   rax
   1400010f1:	48 8b 05 88 a5 00 00 	mov    rax,QWORD PTR [rip+0xa588]        # 14000b680 <.refptr.__native_startup_lock>
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
   140001128:	48 8b 05 61 a5 00 00 	mov    rax,QWORD PTR [rip+0xa561]        # 14000b690 <.refptr.__native_startup_state>
   14000112f:	8b 00                	mov    eax,DWORD PTR [rax]
   140001131:	83 f8 01             	cmp    eax,0x1
   140001134:	75 0a                	jne    140001140 <__tmainCRTStartup+0xb2>
   140001136:	b9 1f 00 00 00       	mov    ecx,0x1f
   14000113b:	e8 68 85 00 00       	call   1400096a8 <_amsg_exit>
   140001140:	48 8b 05 49 a5 00 00 	mov    rax,QWORD PTR [rip+0xa549]        # 14000b690 <.refptr.__native_startup_state>
   140001147:	8b 00                	mov    eax,DWORD PTR [rax]
   140001149:	85 c0                	test   eax,eax
   14000114b:	0f 85 e3 01 00 00    	jne    140001334 <__tmainCRTStartup+0x2a6>
   140001151:	48 8b 05 38 a5 00 00 	mov    rax,QWORD PTR [rip+0xa538]        # 14000b690 <.refptr.__native_startup_state>
   140001158:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000115e:	b9 02 00 00 00       	mov    ecx,0x2
   140001163:	e8 68 7f 00 00       	call   1400090d0 <__acrt_iob_func>
   140001168:	41 b9 00 00 00 00    	mov    r9d,0x0
   14000116e:	41 b8 04 00 00 00    	mov    r8d,0x4
   140001174:	ba 00 00 00 00       	mov    edx,0x0
   140001179:	48 89 c1             	mov    rcx,rax
   14000117c:	e8 bf 85 00 00       	call   140009740 <setvbuf>
   140001181:	48 8d 05 8f fe ff ff 	lea    rax,[rip+0xfffffffffffffe8f]        # 140001017 <safe_flush>
   140001188:	48 89 c1             	mov    rcx,rax
   14000118b:	e8 9f 04 00 00       	call   14000162f <atexit>
   140001190:	85 c0                	test   eax,eax
   140001192:	74 05                	je     140001199 <__tmainCRTStartup+0x10b>
   140001194:	e8 47 85 00 00       	call   1400096e0 <abort>
   140001199:	e8 32 12 00 00       	call   1400023d0 <_pei386_runtime_relocator>
   14000119e:	48 8b 05 7b a5 00 00 	mov    rax,QWORD PTR [rip+0xa57b]        # 14000b720 <.refptr._gnu_exception_handler>
   1400011a5:	48 89 c1             	mov    rcx,rax
   1400011a8:	48 8b 05 a1 f0 00 00 	mov    rax,QWORD PTR [rip+0xf0a1]        # 140010250 <__imp_SetUnhandledExceptionFilter>
   1400011af:	ff d0                	call   rax
   1400011b1:	48 8b 15 b8 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4b8]        # 14000b670 <.refptr.__mingw_oldexcpt_handler>
   1400011b8:	48 89 02             	mov    QWORD PTR [rdx],rax
   1400011bb:	48 8d 05 3e fe ff ff 	lea    rax,[rip+0xfffffffffffffe3e]        # 140001000 <__mingw_invalidParameterHandler>
   1400011c2:	48 89 c1             	mov    rcx,rax
   1400011c5:	e8 a6 7e 00 00       	call   140009070 <_set_invalid_parameter_handler>
   1400011ca:	e8 11 1b 00 00       	call   140002ce0 <_fpreset>
   1400011cf:	e8 18 02 00 00       	call   1400013ec <check_managed_app>
   1400011d4:	89 05 3e de 00 00    	mov    DWORD PTR [rip+0xde3e],eax        # 14000f018 <managedapp>
   1400011da:	48 8b 05 4f a4 00 00 	mov    rax,QWORD PTR [rip+0xa44f]        # 14000b630 <.refptr.__mingw_app_type>
   1400011e1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400011e3:	85 c0                	test   eax,eax
   1400011e5:	74 0c                	je     1400011f3 <__tmainCRTStartup+0x165>
   1400011e7:	b9 02 00 00 00       	mov    ecx,0x2
   1400011ec:	e8 a7 84 00 00       	call   140009698 <__set_app_type>
   1400011f1:	eb 0a                	jmp    1400011fd <__tmainCRTStartup+0x16f>
   1400011f3:	b9 01 00 00 00       	mov    ecx,0x1
   1400011f8:	e8 9b 84 00 00       	call   140009698 <__set_app_type>
   1400011fd:	e8 1e 7d 00 00       	call   140008f20 <__p__fmode>
   140001202:	48 8b 15 07 a5 00 00 	mov    rdx,QWORD PTR [rip+0xa507]        # 14000b710 <.refptr._fmode>
   140001209:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000120b:	89 10                	mov    DWORD PTR [rax],edx
   14000120d:	e8 1e 7d 00 00       	call   140008f30 <__p__commode>
   140001212:	48 8b 15 d7 a4 00 00 	mov    rdx,QWORD PTR [rip+0xa4d7]        # 14000b6f0 <.refptr._commode>
   140001219:	8b 12                	mov    edx,DWORD PTR [rdx]
   14000121b:	89 10                	mov    DWORD PTR [rax],edx
   14000121d:	e8 8e 07 00 00       	call   1400019b0 <_setargv>
   140001222:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140001225:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140001229:	79 0a                	jns    140001235 <__tmainCRTStartup+0x1a7>
   14000122b:	b9 08 00 00 00       	mov    ecx,0x8
   140001230:	e8 73 84 00 00       	call   1400096a8 <_amsg_exit>
   140001235:	48 8b 05 44 a3 00 00 	mov    rax,QWORD PTR [rip+0xa344]        # 14000b580 <.refptr._MINGW_INSTALL_DEBUG_MATHERR>
   14000123c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000123e:	83 f8 01             	cmp    eax,0x1
   140001241:	75 0f                	jne    140001252 <__tmainCRTStartup+0x1c4>
   140001243:	48 8b 05 e6 a4 00 00 	mov    rax,QWORD PTR [rip+0xa4e6]        # 14000b730 <.refptr._matherr>
   14000124a:	48 89 c1             	mov    rcx,rax
   14000124d:	e8 98 12 00 00       	call   1400024ea <__mingw_setusermatherr>
   140001252:	48 8b 05 97 a3 00 00 	mov    rax,QWORD PTR [rip+0xa397]        # 14000b5f0 <.refptr.__globallocalestatus>
   140001259:	8b 00                	mov    eax,DWORD PTR [rax]
   14000125b:	83 f8 ff             	cmp    eax,0xffffffff
   14000125e:	75 0a                	jne    14000126a <__tmainCRTStartup+0x1dc>
   140001260:	b9 ff ff ff ff       	mov    ecx,0xffffffff
   140001265:	e8 46 7e 00 00       	call   1400090b0 <_configthreadlocale>
   14000126a:	48 8b 15 6f a4 00 00 	mov    rdx,QWORD PTR [rip+0xa46f]        # 14000b6e0 <.refptr.__xi_z>
   140001271:	48 8b 05 58 a4 00 00 	mov    rax,QWORD PTR [rip+0xa458]        # 14000b6d0 <.refptr.__xi_a>
   140001278:	48 89 c1             	mov    rcx,rax
   14000127b:	e8 40 7c 00 00       	call   140008ec0 <_initterm_e>
   140001280:	85 c0                	test   eax,eax
   140001282:	74 0a                	je     14000128e <__tmainCRTStartup+0x200>
   140001284:	b9 0a 00 00 00       	mov    ecx,0xa
   140001289:	e8 1a 84 00 00       	call   1400096a8 <_amsg_exit>
   14000128e:	48 8b 05 ab a4 00 00 	mov    rax,QWORD PTR [rip+0xa4ab]        # 14000b740 <.refptr._newmode>
   140001295:	8b 00                	mov    eax,DWORD PTR [rax]
   140001297:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000129a:	48 8b 05 5f a4 00 00 	mov    rax,QWORD PTR [rip+0xa45f]        # 14000b700 <.refptr._dowildcard>
   1400012a1:	44 8b 00             	mov    r8d,DWORD PTR [rax]
   1400012a4:	4c 8d 15 65 dd 00 00 	lea    r10,[rip+0xdd65]        # 14000f010 <envp>
   1400012ab:	48 8d 15 56 dd 00 00 	lea    rdx,[rip+0xdd56]        # 14000f008 <argv>
   1400012b2:	48 8d 05 4b dd 00 00 	lea    rax,[rip+0xdd4b]        # 14000f004 <argc>
   1400012b9:	48 8d 4d ac          	lea    rcx,[rbp-0x54]
   1400012bd:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
   1400012c2:	45 89 c1             	mov    r9d,r8d
   1400012c5:	4d 89 d0             	mov    r8,r10
   1400012c8:	48 89 c1             	mov    rcx,rax
   1400012cb:	e8 b8 83 00 00       	call   140009688 <__getmainargs>
   1400012d0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012d3:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012d7:	79 0a                	jns    1400012e3 <__tmainCRTStartup+0x255>
   1400012d9:	b9 08 00 00 00       	mov    ecx,0x8
   1400012de:	e8 c5 83 00 00       	call   1400096a8 <_amsg_exit>
   1400012e3:	8b 05 1b dd 00 00    	mov    eax,DWORD PTR [rip+0xdd1b]        # 14000f004 <argc>
   1400012e9:	48 8d 15 18 dd 00 00 	lea    rdx,[rip+0xdd18]        # 14000f008 <argv>
   1400012f0:	89 c1                	mov    ecx,eax
   1400012f2:	e8 f9 01 00 00       	call   1400014f0 <duplicate_ppstrings>
   1400012f7:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400012fa:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   1400012fe:	74 0a                	je     14000130a <__tmainCRTStartup+0x27c>
   140001300:	b9 08 00 00 00       	mov    ecx,0x8
   140001305:	e8 9e 83 00 00       	call   1400096a8 <_amsg_exit>
   14000130a:	48 8b 15 af a3 00 00 	mov    rdx,QWORD PTR [rip+0xa3af]        # 14000b6c0 <.refptr.__xc_z>
   140001311:	48 8b 05 98 a3 00 00 	mov    rax,QWORD PTR [rip+0xa398]        # 14000b6b0 <.refptr.__xc_a>
   140001318:	48 89 c1             	mov    rcx,rax
   14000131b:	e8 a0 83 00 00       	call   1400096c0 <_initterm>
   140001320:	e8 62 06 00 00       	call   140001987 <__main>
   140001325:	48 8b 05 64 a3 00 00 	mov    rax,QWORD PTR [rip+0xa364]        # 14000b690 <.refptr.__native_startup_state>
   14000132c:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   140001332:	eb 0a                	jmp    14000133e <__tmainCRTStartup+0x2b0>
   140001334:	c7 05 de dc 00 00 01 	mov    DWORD PTR [rip+0xdcde],0x1        # 14000f01c <has_cctor>
   14000133b:	00 00 00 
   14000133e:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140001342:	75 1e                	jne    140001362 <__tmainCRTStartup+0x2d4>
   140001344:	48 8b 05 35 a3 00 00 	mov    rax,QWORD PTR [rip+0xa335]        # 14000b680 <.refptr.__native_startup_lock>
   14000134b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000134f:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
   140001356:	00 
   140001357:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000135b:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000135f:	48 87 10             	xchg   QWORD PTR [rax],rdx
   140001362:	48 8b 05 77 a2 00 00 	mov    rax,QWORD PTR [rip+0xa277]        # 14000b5e0 <.refptr.__dyn_tls_init_callback>
   140001369:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000136c:	48 85 c0             	test   rax,rax
   14000136f:	74 1c                	je     14000138d <__tmainCRTStartup+0x2ff>
   140001371:	48 8b 05 68 a2 00 00 	mov    rax,QWORD PTR [rip+0xa268]        # 14000b5e0 <.refptr.__dyn_tls_init_callback>
   140001378:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000137b:	41 b8 00 00 00 00    	mov    r8d,0x0
   140001381:	ba 02 00 00 00       	mov    edx,0x2
   140001386:	b9 00 00 00 00       	mov    ecx,0x0
   14000138b:	ff d0                	call   rax
   14000138d:	e8 ae 7b 00 00       	call   140008f40 <__p___initenv>
   140001392:	48 8b 15 77 dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc77]        # 14000f010 <envp>
   140001399:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000139c:	48 8b 0d 6d dc 00 00 	mov    rcx,QWORD PTR [rip+0xdc6d]        # 14000f010 <envp>
   1400013a3:	48 8b 15 5e dc 00 00 	mov    rdx,QWORD PTR [rip+0xdc5e]        # 14000f008 <argv>
   1400013aa:	8b 05 54 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc54]        # 14000f004 <argc>
   1400013b0:	49 89 c8             	mov    r8,rcx
   1400013b3:	89 c1                	mov    ecx,eax
   1400013b5:	e8 7f 04 00 00       	call   140001839 <main>
   1400013ba:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   1400013bd:	8b 05 55 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc55]        # 14000f018 <managedapp>
   1400013c3:	85 c0                	test   eax,eax
   1400013c5:	75 0a                	jne    1400013d1 <__tmainCRTStartup+0x343>
   1400013c7:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013ca:	89 c1                	mov    ecx,eax
   1400013cc:	e8 1f 83 00 00       	call   1400096f0 <exit>
   1400013d1:	8b 05 45 dc 00 00    	mov    eax,DWORD PTR [rip+0xdc45]        # 14000f01c <has_cctor>
   1400013d7:	85 c0                	test   eax,eax
   1400013d9:	75 05                	jne    1400013e0 <__tmainCRTStartup+0x352>
   1400013db:	e8 d0 82 00 00       	call   1400096b0 <_cexit>
   1400013e0:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   1400013e3:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400013ea:	5d                   	pop    rbp
   1400013eb:	c3                   	ret

00000001400013ec <check_managed_app>:
   1400013ec:	55                   	push   rbp
   1400013ed:	48 89 e5             	mov    rbp,rsp
   1400013f0:	48 83 ec 20          	sub    rsp,0x20
   1400013f4:	48 8b 05 45 a2 00 00 	mov    rax,QWORD PTR [rip+0xa245]        # 14000b640 <.refptr.__mingw_initltsdrot_force>
   1400013fb:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140001401:	48 8b 05 48 a2 00 00 	mov    rax,QWORD PTR [rip+0xa248]        # 14000b650 <.refptr.__mingw_initltsdyn_force>
   140001408:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000140e:	48 8b 05 4b a2 00 00 	mov    rax,QWORD PTR [rip+0xa24b]        # 14000b660 <.refptr.__mingw_initltssuo_force>
   140001415:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   14000141b:	48 8b 05 7e a1 00 00 	mov    rax,QWORD PTR [rip+0xa17e]        # 14000b5a0 <.refptr.__ImageBase>
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
   140001511:	e8 0a 82 00 00       	call   140009720 <malloc>
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
   14000155c:	e8 f7 81 00 00       	call   140009758 <strlen>
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
   140001585:	e8 96 81 00 00       	call   140009720 <malloc>
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
   1400015e8:	e8 3b 81 00 00       	call   140009728 <memcpy>
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
   140001642:	e8 91 80 00 00       	call   1400096d8 <_crt_atexit>
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
   140001682:	ff 15 98 eb 00 00    	call   QWORD PTR [rip+0xeb98]        # 140010220 <__imp_GetModuleHandleA>
   140001688:	48 89 c3             	mov    rbx,rax
   14000168b:	48 85 c0             	test   rax,rax
   14000168e:	74 70                	je     140001700 <__gcc_register_frame+0x90>
   140001690:	48 8d 0d 69 99 00 00 	lea    rcx,[rip+0x9969]        # 14000b000 <.rdata>
   140001697:	ff 15 a3 eb 00 00    	call   QWORD PTR [rip+0xeba3]        # 140010240 <__imp_LoadLibraryA>
   14000169d:	4c 8b 0d 84 eb 00 00 	mov    r9,QWORD PTR [rip+0xeb84]        # 140010228 <__imp_GetProcAddress>
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
   14000174e:	48 ff 25 b3 ea 00 00 	rex.W jmp QWORD PTR [rip+0xeab3]        # 140010208 <__imp_FreeLibrary>
   140001755:	0f 1f 00             	nop    DWORD PTR [rax]
   140001758:	48 83 c4 20          	add    rsp,0x20
   14000175c:	5d                   	pop    rbp
   14000175d:	c3                   	ret
   14000175e:	90                   	nop
   14000175f:	90                   	nop

0000000140001760 <vsock_sock_new>:
   140001760:	55                   	push   rbp
   140001761:	48 89 e5             	mov    rbp,rsp
   140001764:	48 83 ec 30          	sub    rsp,0x30
   140001768:	b9 10 00 00 00       	mov    ecx,0x10
   14000176d:	e8 ae 7f 00 00       	call   140009720 <malloc>
   140001772:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001776:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000177a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140001780:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001784:	c7 40 04 00 00 00 00 	mov    DWORD PTR [rax+0x4],0x0
   14000178b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000178f:	48 83 c0 08          	add    rax,0x8
   140001793:	c7 00 76 73 6f 63    	mov    DWORD PTR [rax],0x636f7376
   140001799:	c7 40 03 63 6b 30 00 	mov    DWORD PTR [rax+0x3],0x306b63
   1400017a0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400017a4:	48 83 c4 30          	add    rsp,0x30
   1400017a8:	5d                   	pop    rbp
   1400017a9:	c3                   	ret

00000001400017aa <vsock_release>:
   1400017aa:	55                   	push   rbp
   1400017ab:	48 89 e5             	mov    rbp,rsp
   1400017ae:	48 83 ec 20          	sub    rsp,0x20
   1400017b2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400017b6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017ba:	c7 40 04 01 00 00 00 	mov    DWORD PTR [rax+0x4],0x1
   1400017c1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017c5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400017c7:	8d 50 ff             	lea    edx,[rax-0x1]
   1400017ca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017ce:	89 10                	mov    DWORD PTR [rax],edx
   1400017d0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017d4:	8b 00                	mov    eax,DWORD PTR [rax]
   1400017d6:	85 c0                	test   eax,eax
   1400017d8:	75 0c                	jne    1400017e6 <vsock_release+0x3c>
   1400017da:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017de:	48 89 c1             	mov    rcx,rax
   1400017e1:	e8 2a 7f 00 00       	call   140009710 <free>
   1400017e6:	90                   	nop
   1400017e7:	48 83 c4 20          	add    rsp,0x20
   1400017eb:	5d                   	pop    rbp
   1400017ec:	c3                   	ret

00000001400017ed <vsock_process_pkt>:
   1400017ed:	55                   	push   rbp
   1400017ee:	48 89 e5             	mov    rbp,rsp
   1400017f1:	48 83 ec 20          	sub    rsp,0x20
   1400017f5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400017f9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400017fd:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001800:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140001803:	85 c0                	test   eax,eax
   140001805:	74 11                	je     140001818 <vsock_process_pkt+0x2b>
   140001807:	48 8d 05 42 98 00 00 	lea    rax,[rip+0x9842]        # 14000b050 <.rdata>
   14000180e:	48 89 c1             	mov    rcx,rax
   140001811:	e8 22 7f 00 00       	call   140009738 <puts>
   140001816:	eb 1a                	jmp    140001832 <vsock_process_pkt+0x45>
   140001818:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000181c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000181f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140001823:	48 8d 05 30 98 00 00 	lea    rax,[rip+0x9830]        # 14000b05a <.rdata+0xa>
   14000182a:	48 89 c1             	mov    rcx,rax
   14000182d:	e8 ae 19 00 00       	call   1400031e0 <__mingw_printf>
   140001832:	90                   	nop
   140001833:	48 83 c4 20          	add    rsp,0x20
   140001837:	5d                   	pop    rbp
   140001838:	c3                   	ret

0000000140001839 <main>:
   140001839:	55                   	push   rbp
   14000183a:	48 89 e5             	mov    rbp,rsp
   14000183d:	48 83 ec 30          	sub    rsp,0x30
   140001841:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140001844:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140001848:	e8 3a 01 00 00       	call   140001987 <__main>
   14000184d:	e8 0e ff ff ff       	call   140001760 <vsock_sock_new>
   140001852:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001856:	b9 50 00 00 00       	mov    ecx,0x50
   14000185b:	e8 c0 7e 00 00       	call   140009720 <malloc>
   140001860:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001864:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001868:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   14000186c:	48 89 10             	mov    QWORD PTR [rax],rdx
   14000186f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001873:	c7 40 48 10 00 00 00 	mov    DWORD PTR [rax+0x48],0x10
   14000187a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000187e:	48 83 c0 08          	add    rax,0x8
   140001882:	41 b8 10 00 00 00    	mov    r8d,0x10
   140001888:	ba 50 00 00 00       	mov    edx,0x50
   14000188d:	48 89 c1             	mov    rcx,rax
   140001890:	e8 9b 7e 00 00       	call   140009730 <memset>
   140001895:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001899:	48 89 c1             	mov    rcx,rax
   14000189c:	e8 09 ff ff ff       	call   1400017aa <vsock_release>
   1400018a1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400018a5:	48 89 c1             	mov    rcx,rax
   1400018a8:	e8 40 ff ff ff       	call   1400017ed <vsock_process_pkt>
   1400018ad:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400018b1:	48 89 c1             	mov    rcx,rax
   1400018b4:	e8 57 7e 00 00       	call   140009710 <free>
   1400018b9:	b8 00 00 00 00       	mov    eax,0x0
   1400018be:	48 83 c4 30          	add    rsp,0x30
   1400018c2:	5d                   	pop    rbp
   1400018c3:	c3                   	ret
   1400018c4:	90                   	nop
   1400018c5:	90                   	nop
   1400018c6:	90                   	nop
   1400018c7:	90                   	nop
   1400018c8:	90                   	nop
   1400018c9:	90                   	nop
   1400018ca:	90                   	nop
   1400018cb:	90                   	nop
   1400018cc:	90                   	nop
   1400018cd:	90                   	nop
   1400018ce:	90                   	nop
   1400018cf:	90                   	nop

00000001400018d0 <__do_global_dtors>:
   1400018d0:	55                   	push   rbp
   1400018d1:	48 89 e5             	mov    rbp,rsp
   1400018d4:	48 83 ec 20          	sub    rsp,0x20
   1400018d8:	eb 1e                	jmp    1400018f8 <__do_global_dtors+0x28>
   1400018da:	48 8b 05 2f 87 00 00 	mov    rax,QWORD PTR [rip+0x872f]        # 14000a010 <p.0>
   1400018e1:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400018e4:	ff d0                	call   rax
   1400018e6:	48 8b 05 23 87 00 00 	mov    rax,QWORD PTR [rip+0x8723]        # 14000a010 <p.0>
   1400018ed:	48 83 c0 08          	add    rax,0x8
   1400018f1:	48 89 05 18 87 00 00 	mov    QWORD PTR [rip+0x8718],rax        # 14000a010 <p.0>
   1400018f8:	48 8b 05 11 87 00 00 	mov    rax,QWORD PTR [rip+0x8711]        # 14000a010 <p.0>
   1400018ff:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001902:	48 85 c0             	test   rax,rax
   140001905:	75 d3                	jne    1400018da <__do_global_dtors+0xa>
   140001907:	90                   	nop
   140001908:	90                   	nop
   140001909:	48 83 c4 20          	add    rsp,0x20
   14000190d:	5d                   	pop    rbp
   14000190e:	c3                   	ret

000000014000190f <__do_global_ctors>:
   14000190f:	55                   	push   rbp
   140001910:	48 89 e5             	mov    rbp,rsp
   140001913:	48 83 ec 30          	sub    rsp,0x30
   140001917:	48 8b 05 72 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c72]        # 14000b590 <.refptr.__CTOR_LIST__>
   14000191e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001921:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140001924:	83 7d fc ff          	cmp    DWORD PTR [rbp-0x4],0xffffffff
   140001928:	75 25                	jne    14000194f <__do_global_ctors+0x40>
   14000192a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001931:	eb 04                	jmp    140001937 <__do_global_ctors+0x28>
   140001933:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001937:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000193a:	8d 50 01             	lea    edx,[rax+0x1]
   14000193d:	48 8b 05 4c 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c4c]        # 14000b590 <.refptr.__CTOR_LIST__>
   140001944:	89 d2                	mov    edx,edx
   140001946:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   14000194a:	48 85 c0             	test   rax,rax
   14000194d:	75 e4                	jne    140001933 <__do_global_ctors+0x24>
   14000194f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001952:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140001955:	eb 14                	jmp    14000196b <__do_global_ctors+0x5c>
   140001957:	48 8b 05 32 9c 00 00 	mov    rax,QWORD PTR [rip+0x9c32]        # 14000b590 <.refptr.__CTOR_LIST__>
   14000195e:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140001961:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
   140001965:	ff d0                	call   rax
   140001967:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   14000196b:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000196f:	75 e6                	jne    140001957 <__do_global_ctors+0x48>
   140001971:	48 8d 05 58 ff ff ff 	lea    rax,[rip+0xffffffffffffff58]        # 1400018d0 <__do_global_dtors>
   140001978:	48 89 c1             	mov    rcx,rax
   14000197b:	e8 af fc ff ff       	call   14000162f <atexit>
   140001980:	90                   	nop
   140001981:	48 83 c4 30          	add    rsp,0x30
   140001985:	5d                   	pop    rbp
   140001986:	c3                   	ret

0000000140001987 <__main>:
   140001987:	55                   	push   rbp
   140001988:	48 89 e5             	mov    rbp,rsp
   14000198b:	48 83 ec 20          	sub    rsp,0x20
   14000198f:	8b 05 eb d6 00 00    	mov    eax,DWORD PTR [rip+0xd6eb]        # 14000f080 <initialized>
   140001995:	85 c0                	test   eax,eax
   140001997:	75 0f                	jne    1400019a8 <__main+0x21>
   140001999:	c7 05 dd d6 00 00 01 	mov    DWORD PTR [rip+0xd6dd],0x1        # 14000f080 <initialized>
   1400019a0:	00 00 00 
   1400019a3:	e8 67 ff ff ff       	call   14000190f <__do_global_ctors>
   1400019a8:	90                   	nop
   1400019a9:	48 83 c4 20          	add    rsp,0x20
   1400019ad:	5d                   	pop    rbp
   1400019ae:	c3                   	ret
   1400019af:	90                   	nop

00000001400019b0 <_setargv>:
   1400019b0:	55                   	push   rbp
   1400019b1:	48 89 e5             	mov    rbp,rsp
   1400019b4:	b8 00 00 00 00       	mov    eax,0x0
   1400019b9:	5d                   	pop    rbp
   1400019ba:	c3                   	ret
   1400019bb:	90                   	nop
   1400019bc:	90                   	nop
   1400019bd:	90                   	nop
   1400019be:	90                   	nop
   1400019bf:	90                   	nop

00000001400019c0 <__dyn_tls_init>:
   1400019c0:	55                   	push   rbp
   1400019c1:	48 89 e5             	mov    rbp,rsp
   1400019c4:	48 83 ec 30          	sub    rsp,0x30
   1400019c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400019cc:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400019cf:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400019d3:	48 8b 05 96 9b 00 00 	mov    rax,QWORD PTR [rip+0x9b96]        # 14000b570 <.refptr._CRT_MT>
   1400019da:	8b 00                	mov    eax,DWORD PTR [rax]
   1400019dc:	83 f8 02             	cmp    eax,0x2
   1400019df:	74 0d                	je     1400019ee <__dyn_tls_init+0x2e>
   1400019e1:	48 8b 05 88 9b 00 00 	mov    rax,QWORD PTR [rip+0x9b88]        # 14000b570 <.refptr._CRT_MT>
   1400019e8:	c7 00 02 00 00 00    	mov    DWORD PTR [rax],0x2
   1400019ee:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   1400019f2:	74 1e                	je     140001a12 <__dyn_tls_init+0x52>
   1400019f4:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   1400019f8:	75 5b                	jne    140001a55 <__dyn_tls_init+0x95>
   1400019fa:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   1400019fe:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a01:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001a05:	49 89 c8             	mov    r8,rcx
   140001a08:	48 89 c1             	mov    rcx,rax
   140001a0b:	e8 d1 11 00 00       	call   140002be1 <__mingw_TLScallback>
   140001a10:	eb 43                	jmp    140001a55 <__dyn_tls_init+0x95>
   140001a12:	48 8d 05 df 9e 00 00 	lea    rax,[rip+0x9edf]        # 14000b8f8 <___crt_xd_start__>
   140001a19:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001a1d:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a22:	eb 22                	jmp    140001a46 <__dyn_tls_init+0x86>
   140001a24:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140001a28:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001a2c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a30:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a33:	48 85 c0             	test   rax,rax
   140001a36:	74 09                	je     140001a41 <__dyn_tls_init+0x81>
   140001a38:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001a3c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140001a3f:	ff d0                	call   rax
   140001a41:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140001a46:	48 8d 05 b3 9e 00 00 	lea    rax,[rip+0x9eb3]        # 14000b900 <__xd_z>
   140001a4d:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140001a51:	75 d1                	jne    140001a24 <__dyn_tls_init+0x64>
   140001a53:	eb 01                	jmp    140001a56 <__dyn_tls_init+0x96>
   140001a55:	90                   	nop
   140001a56:	48 83 c4 30          	add    rsp,0x30
   140001a5a:	5d                   	pop    rbp
   140001a5b:	c3                   	ret

0000000140001a5c <__tlregdtor>:
   140001a5c:	55                   	push   rbp
   140001a5d:	48 89 e5             	mov    rbp,rsp
   140001a60:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a64:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140001a69:	75 07                	jne    140001a72 <__tlregdtor+0x16>
   140001a6b:	b8 00 00 00 00       	mov    eax,0x0
   140001a70:	eb 05                	jmp    140001a77 <__tlregdtor+0x1b>
   140001a72:	b8 00 00 00 00       	mov    eax,0x0
   140001a77:	5d                   	pop    rbp
   140001a78:	c3                   	ret

0000000140001a79 <__dyn_tls_dtor>:
   140001a79:	55                   	push   rbp
   140001a7a:	48 89 e5             	mov    rbp,rsp
   140001a7d:	48 83 ec 20          	sub    rsp,0x20
   140001a81:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001a85:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140001a88:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140001a8c:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140001a90:	74 06                	je     140001a98 <__dyn_tls_dtor+0x1f>
   140001a92:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140001a96:	75 18                	jne    140001ab0 <__dyn_tls_dtor+0x37>
   140001a98:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140001a9c:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140001a9f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001aa3:	49 89 c8             	mov    r8,rcx
   140001aa6:	48 89 c1             	mov    rcx,rax
   140001aa9:	e8 33 11 00 00       	call   140002be1 <__mingw_TLScallback>
   140001aae:	eb 01                	jmp    140001ab1 <__dyn_tls_dtor+0x38>
   140001ab0:	90                   	nop
   140001ab1:	48 83 c4 20          	add    rsp,0x20
   140001ab5:	5d                   	pop    rbp
   140001ab6:	c3                   	ret
   140001ab7:	90                   	nop
   140001ab8:	90                   	nop
   140001ab9:	90                   	nop
   140001aba:	90                   	nop
   140001abb:	90                   	nop
   140001abc:	90                   	nop
   140001abd:	90                   	nop
   140001abe:	90                   	nop
   140001abf:	90                   	nop

0000000140001ac0 <_matherr>:
   140001ac0:	55                   	push   rbp
   140001ac1:	53                   	push   rbx
   140001ac2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140001ac9:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140001ace:	0f 29 75 00          	movaps XMMWORD PTR [rbp+0x0],xmm6
   140001ad2:	0f 29 7d 10          	movaps XMMWORD PTR [rbp+0x10],xmm7
   140001ad6:	44 0f 29 45 20       	movaps XMMWORD PTR [rbp+0x20],xmm8
   140001adb:	48 89 4d 50          	mov    QWORD PTR [rbp+0x50],rcx
   140001adf:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001ae3:	8b 00                	mov    eax,DWORD PTR [rax]
   140001ae5:	83 f8 06             	cmp    eax,0x6
   140001ae8:	74 56                	je     140001b40 <_matherr+0x80>
   140001aea:	83 f8 06             	cmp    eax,0x6
   140001aed:	7f 78                	jg     140001b67 <_matherr+0xa7>
   140001aef:	83 f8 05             	cmp    eax,0x5
   140001af2:	74 59                	je     140001b4d <_matherr+0x8d>
   140001af4:	83 f8 05             	cmp    eax,0x5
   140001af7:	7f 6e                	jg     140001b67 <_matherr+0xa7>
   140001af9:	83 f8 04             	cmp    eax,0x4
   140001afc:	74 5c                	je     140001b5a <_matherr+0x9a>
   140001afe:	83 f8 04             	cmp    eax,0x4
   140001b01:	7f 64                	jg     140001b67 <_matherr+0xa7>
   140001b03:	83 f8 03             	cmp    eax,0x3
   140001b06:	74 2b                	je     140001b33 <_matherr+0x73>
   140001b08:	83 f8 03             	cmp    eax,0x3
   140001b0b:	7f 5a                	jg     140001b67 <_matherr+0xa7>
   140001b0d:	83 f8 01             	cmp    eax,0x1
   140001b10:	74 07                	je     140001b19 <_matherr+0x59>
   140001b12:	83 f8 02             	cmp    eax,0x2
   140001b15:	74 0f                	je     140001b26 <_matherr+0x66>
   140001b17:	eb 4e                	jmp    140001b67 <_matherr+0xa7>
   140001b19:	48 8d 05 a0 95 00 00 	lea    rax,[rip+0x95a0]        # 14000b0c0 <.rdata>
   140001b20:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b24:	eb 4d                	jmp    140001b73 <_matherr+0xb3>
   140001b26:	48 8d 05 b2 95 00 00 	lea    rax,[rip+0x95b2]        # 14000b0df <.rdata+0x1f>
   140001b2d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b31:	eb 40                	jmp    140001b73 <_matherr+0xb3>
   140001b33:	48 8d 05 c6 95 00 00 	lea    rax,[rip+0x95c6]        # 14000b100 <.rdata+0x40>
   140001b3a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b3e:	eb 33                	jmp    140001b73 <_matherr+0xb3>
   140001b40:	48 8d 05 d9 95 00 00 	lea    rax,[rip+0x95d9]        # 14000b120 <.rdata+0x60>
   140001b47:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b4b:	eb 26                	jmp    140001b73 <_matherr+0xb3>
   140001b4d:	48 8d 05 f4 95 00 00 	lea    rax,[rip+0x95f4]        # 14000b148 <.rdata+0x88>
   140001b54:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b58:	eb 19                	jmp    140001b73 <_matherr+0xb3>
   140001b5a:	48 8d 05 0f 96 00 00 	lea    rax,[rip+0x960f]        # 14000b170 <.rdata+0xb0>
   140001b61:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b65:	eb 0c                	jmp    140001b73 <_matherr+0xb3>
   140001b67:	48 8d 05 38 96 00 00 	lea    rax,[rip+0x9638]        # 14000b1a6 <.rdata+0xe6>
   140001b6e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001b72:	90                   	nop
   140001b73:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b77:	f2 44 0f 10 40 20    	movsd  xmm8,QWORD PTR [rax+0x20]
   140001b7d:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b81:	f2 0f 10 78 18       	movsd  xmm7,QWORD PTR [rax+0x18]
   140001b86:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b8a:	f2 0f 10 70 10       	movsd  xmm6,QWORD PTR [rax+0x10]
   140001b8f:	48 8b 45 50          	mov    rax,QWORD PTR [rbp+0x50]
   140001b93:	48 8b 58 08          	mov    rbx,QWORD PTR [rax+0x8]
   140001b97:	b9 02 00 00 00       	mov    ecx,0x2
   140001b9c:	e8 2f 75 00 00       	call   1400090d0 <__acrt_iob_func>
   140001ba1:	48 89 c1             	mov    rcx,rax
   140001ba4:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140001ba8:	48 8d 05 09 96 00 00 	lea    rax,[rip+0x9609]        # 14000b1b8 <.rdata+0xf8>
   140001baf:	f2 44 0f 11 44 24 30 	movsd  QWORD PTR [rsp+0x30],xmm8
   140001bb6:	f2 0f 11 7c 24 28    	movsd  QWORD PTR [rsp+0x28],xmm7
   140001bbc:	f2 0f 11 74 24 20    	movsd  QWORD PTR [rsp+0x20],xmm6
   140001bc2:	49 89 d9             	mov    r9,rbx
   140001bc5:	49 89 d0             	mov    r8,rdx
   140001bc8:	48 89 c2             	mov    rdx,rax
   140001bcb:	e8 30 7b 00 00       	call   140009700 <fprintf>
   140001bd0:	b8 00 00 00 00       	mov    eax,0x0
   140001bd5:	0f 28 75 00          	movaps xmm6,XMMWORD PTR [rbp+0x0]
   140001bd9:	0f 28 7d 10          	movaps xmm7,XMMWORD PTR [rbp+0x10]
   140001bdd:	44 0f 28 45 20       	movaps xmm8,XMMWORD PTR [rbp+0x20]
   140001be2:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140001be9:	5b                   	pop    rbx
   140001bea:	5d                   	pop    rbp
   140001beb:	c3                   	ret
   140001bec:	90                   	nop
   140001bed:	90                   	nop
   140001bee:	90                   	nop
   140001bef:	90                   	nop

0000000140001bf0 <__report_error>:
   140001bf0:	55                   	push   rbp
   140001bf1:	53                   	push   rbx
   140001bf2:	48 83 ec 38          	sub    rsp,0x38
   140001bf6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140001bfb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140001bff:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140001c03:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140001c07:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140001c0b:	48 8d 45 28          	lea    rax,[rbp+0x28]
   140001c0f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140001c13:	b9 02 00 00 00       	mov    ecx,0x2
   140001c18:	e8 b3 74 00 00       	call   1400090d0 <__acrt_iob_func>
   140001c1d:	48 89 c1             	mov    rcx,rax
   140001c20:	48 8d 05 c9 95 00 00 	lea    rax,[rip+0x95c9]        # 14000b1f0 <.rdata>
   140001c27:	48 89 c2             	mov    rdx,rax
   140001c2a:	e8 d1 7a 00 00       	call   140009700 <fprintf>
   140001c2f:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140001c33:	b9 02 00 00 00       	mov    ecx,0x2
   140001c38:	e8 93 74 00 00       	call   1400090d0 <__acrt_iob_func>
   140001c3d:	48 89 c1             	mov    rcx,rax
   140001c40:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140001c44:	49 89 d8             	mov    r8,rbx
   140001c47:	48 89 c2             	mov    rdx,rax
   140001c4a:	e8 19 7b 00 00       	call   140009768 <vfprintf>
   140001c4f:	e8 8c 7a 00 00       	call   1400096e0 <abort>
   140001c54:	90                   	nop

0000000140001c55 <mark_section_writable>:
   140001c55:	55                   	push   rbp
   140001c56:	48 89 e5             	mov    rbp,rsp
   140001c59:	48 83 ec 60          	sub    rsp,0x60
   140001c5d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140001c61:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001c68:	e9 82 00 00 00       	jmp    140001cef <mark_section_writable+0x9a>
   140001c6d:	48 8b 0d 6c d4 00 00 	mov    rcx,QWORD PTR [rip+0xd46c]        # 14000f0e0 <the_secs>
   140001c74:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c77:	48 63 d0             	movsxd rdx,eax
   140001c7a:	48 89 d0             	mov    rax,rdx
   140001c7d:	48 c1 e0 02          	shl    rax,0x2
   140001c81:	48 01 d0             	add    rax,rdx
   140001c84:	48 c1 e0 03          	shl    rax,0x3
   140001c88:	48 01 c8             	add    rax,rcx
   140001c8b:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001c8f:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001c93:	72 56                	jb     140001ceb <mark_section_writable+0x96>
   140001c95:	48 8b 0d 44 d4 00 00 	mov    rcx,QWORD PTR [rip+0xd444]        # 14000f0e0 <the_secs>
   140001c9c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001c9f:	48 63 d0             	movsxd rdx,eax
   140001ca2:	48 89 d0             	mov    rax,rdx
   140001ca5:	48 c1 e0 02          	shl    rax,0x2
   140001ca9:	48 01 d0             	add    rax,rdx
   140001cac:	48 c1 e0 03          	shl    rax,0x3
   140001cb0:	48 01 c8             	add    rax,rcx
   140001cb3:	48 8b 48 18          	mov    rcx,QWORD PTR [rax+0x18]
   140001cb7:	4c 8b 05 22 d4 00 00 	mov    r8,QWORD PTR [rip+0xd422]        # 14000f0e0 <the_secs>
   140001cbe:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001cc1:	48 63 d0             	movsxd rdx,eax
   140001cc4:	48 89 d0             	mov    rax,rdx
   140001cc7:	48 c1 e0 02          	shl    rax,0x2
   140001ccb:	48 01 d0             	add    rax,rdx
   140001cce:	48 c1 e0 03          	shl    rax,0x3
   140001cd2:	4c 01 c0             	add    rax,r8
   140001cd5:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
   140001cd9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001cdc:	89 c0                	mov    eax,eax
   140001cde:	48 01 c8             	add    rax,rcx
   140001ce1:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140001ce5:	0f 82 41 02 00 00    	jb     140001f2c <mark_section_writable+0x2d7>
   140001ceb:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001cef:	8b 05 f3 d3 00 00    	mov    eax,DWORD PTR [rip+0xd3f3]        # 14000f0e8 <maxSections>
   140001cf5:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001cf8:	0f 8c 6f ff ff ff    	jl     140001c6d <mark_section_writable+0x18>
   140001cfe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d02:	48 89 c1             	mov    rcx,rax
   140001d05:	e8 c1 11 00 00       	call   140002ecb <__mingw_GetSectionForAddress>
   140001d0a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140001d0e:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140001d13:	75 13                	jne    140001d28 <mark_section_writable+0xd3>
   140001d15:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140001d19:	48 8d 0d f0 94 00 00 	lea    rcx,[rip+0x94f0]        # 14000b210 <.rdata+0x20>
   140001d20:	48 89 c2             	mov    rdx,rax
   140001d23:	e8 c8 fe ff ff       	call   140001bf0 <__report_error>
   140001d28:	48 8b 0d b1 d3 00 00 	mov    rcx,QWORD PTR [rip+0xd3b1]        # 14000f0e0 <the_secs>
   140001d2f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d32:	48 63 d0             	movsxd rdx,eax
   140001d35:	48 89 d0             	mov    rax,rdx
   140001d38:	48 c1 e0 02          	shl    rax,0x2
   140001d3c:	48 01 d0             	add    rax,rdx
   140001d3f:	48 c1 e0 03          	shl    rax,0x3
   140001d43:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001d47:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d4b:	48 89 42 20          	mov    QWORD PTR [rdx+0x20],rax
   140001d4f:	48 8b 0d 8a d3 00 00 	mov    rcx,QWORD PTR [rip+0xd38a]        # 14000f0e0 <the_secs>
   140001d56:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d59:	48 63 d0             	movsxd rdx,eax
   140001d5c:	48 89 d0             	mov    rax,rdx
   140001d5f:	48 c1 e0 02          	shl    rax,0x2
   140001d63:	48 01 d0             	add    rax,rdx
   140001d66:	48 c1 e0 03          	shl    rax,0x3
   140001d6a:	48 01 c8             	add    rax,rcx
   140001d6d:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140001d73:	e8 9f 12 00 00       	call   140003017 <_GetPEImageBase>
   140001d78:	48 89 c1             	mov    rcx,rax
   140001d7b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001d7f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140001d82:	41 89 c1             	mov    r9d,eax
   140001d85:	4c 8b 05 54 d3 00 00 	mov    r8,QWORD PTR [rip+0xd354]        # 14000f0e0 <the_secs>
   140001d8c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001d8f:	48 63 d0             	movsxd rdx,eax
   140001d92:	48 89 d0             	mov    rax,rdx
   140001d95:	48 c1 e0 02          	shl    rax,0x2
   140001d99:	48 01 d0             	add    rax,rdx
   140001d9c:	48 c1 e0 03          	shl    rax,0x3
   140001da0:	4c 01 c0             	add    rax,r8
   140001da3:	4a 8d 14 09          	lea    rdx,[rcx+r9*1]
   140001da7:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
   140001dab:	48 8b 0d 2e d3 00 00 	mov    rcx,QWORD PTR [rip+0xd32e]        # 14000f0e0 <the_secs>
   140001db2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001db5:	48 63 d0             	movsxd rdx,eax
   140001db8:	48 89 d0             	mov    rax,rdx
   140001dbb:	48 c1 e0 02          	shl    rax,0x2
   140001dbf:	48 01 d0             	add    rax,rdx
   140001dc2:	48 c1 e0 03          	shl    rax,0x3
   140001dc6:	48 01 c8             	add    rax,rcx
   140001dc9:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   140001dcd:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140001dd1:	41 b8 30 00 00 00    	mov    r8d,0x30
   140001dd7:	48 89 c1             	mov    rcx,rax
   140001dda:	48 8b 05 8f e4 00 00 	mov    rax,QWORD PTR [rip+0xe48f]        # 140010270 <__imp_VirtualQuery>
   140001de1:	ff d0                	call   rax
   140001de3:	48 85 c0             	test   rax,rax
   140001de6:	75 3f                	jne    140001e27 <mark_section_writable+0x1d2>
   140001de8:	48 8b 0d f1 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd2f1]        # 14000f0e0 <the_secs>
   140001def:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001df2:	48 63 d0             	movsxd rdx,eax
   140001df5:	48 89 d0             	mov    rax,rdx
   140001df8:	48 c1 e0 02          	shl    rax,0x2
   140001dfc:	48 01 d0             	add    rax,rdx
   140001dff:	48 c1 e0 03          	shl    rax,0x3
   140001e03:	48 01 c8             	add    rax,rcx
   140001e06:	48 8b 50 18          	mov    rdx,QWORD PTR [rax+0x18]
   140001e0a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140001e0e:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140001e11:	89 c1                	mov    ecx,eax
   140001e13:	48 8d 05 16 94 00 00 	lea    rax,[rip+0x9416]        # 14000b230 <.rdata+0x40>
   140001e1a:	49 89 d0             	mov    r8,rdx
   140001e1d:	89 ca                	mov    edx,ecx
   140001e1f:	48 89 c1             	mov    rcx,rax
   140001e22:	e8 c9 fd ff ff       	call   140001bf0 <__report_error>
   140001e27:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e2a:	83 f8 40             	cmp    eax,0x40
   140001e2d:	0f 84 e8 00 00 00    	je     140001f1b <mark_section_writable+0x2c6>
   140001e33:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e36:	83 f8 04             	cmp    eax,0x4
   140001e39:	0f 84 dc 00 00 00    	je     140001f1b <mark_section_writable+0x2c6>
   140001e3f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e42:	3d 80 00 00 00       	cmp    eax,0x80
   140001e47:	0f 84 ce 00 00 00    	je     140001f1b <mark_section_writable+0x2c6>
   140001e4d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e50:	83 f8 08             	cmp    eax,0x8
   140001e53:	0f 84 c2 00 00 00    	je     140001f1b <mark_section_writable+0x2c6>
   140001e59:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140001e5c:	83 f8 02             	cmp    eax,0x2
   140001e5f:	75 09                	jne    140001e6a <mark_section_writable+0x215>
   140001e61:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140001e68:	eb 07                	jmp    140001e71 <mark_section_writable+0x21c>
   140001e6a:	c7 45 f8 40 00 00 00 	mov    DWORD PTR [rbp-0x8],0x40
   140001e71:	48 8b 0d 68 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd268]        # 14000f0e0 <the_secs>
   140001e78:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001e7b:	48 63 d0             	movsxd rdx,eax
   140001e7e:	48 89 d0             	mov    rax,rdx
   140001e81:	48 c1 e0 02          	shl    rax,0x2
   140001e85:	48 01 d0             	add    rax,rdx
   140001e88:	48 c1 e0 03          	shl    rax,0x3
   140001e8c:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001e90:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001e94:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
   140001e98:	48 8b 0d 41 d2 00 00 	mov    rcx,QWORD PTR [rip+0xd241]        # 14000f0e0 <the_secs>
   140001e9f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ea2:	48 63 d0             	movsxd rdx,eax
   140001ea5:	48 89 d0             	mov    rax,rdx
   140001ea8:	48 c1 e0 02          	shl    rax,0x2
   140001eac:	48 01 d0             	add    rax,rdx
   140001eaf:	48 c1 e0 03          	shl    rax,0x3
   140001eb3:	48 8d 14 01          	lea    rdx,[rcx+rax*1]
   140001eb7:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140001ebb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
   140001ebf:	48 8b 0d 1a d2 00 00 	mov    rcx,QWORD PTR [rip+0xd21a]        # 14000f0e0 <the_secs>
   140001ec6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001ec9:	48 63 d0             	movsxd rdx,eax
   140001ecc:	48 89 d0             	mov    rax,rdx
   140001ecf:	48 c1 e0 02          	shl    rax,0x2
   140001ed3:	48 01 d0             	add    rax,rdx
   140001ed6:	48 c1 e0 03          	shl    rax,0x3
   140001eda:	48 01 c8             	add    rax,rcx
   140001edd:	49 89 c0             	mov    r8,rax
   140001ee0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140001ee4:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140001ee8:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140001eeb:	4d 89 c1             	mov    r9,r8
   140001eee:	41 89 c8             	mov    r8d,ecx
   140001ef1:	48 89 c1             	mov    rcx,rax
   140001ef4:	48 8b 05 6d e3 00 00 	mov    rax,QWORD PTR [rip+0xe36d]        # 140010268 <__imp_VirtualProtect>
   140001efb:	ff d0                	call   rax
   140001efd:	85 c0                	test   eax,eax
   140001eff:	75 1a                	jne    140001f1b <mark_section_writable+0x2c6>
   140001f01:	48 8b 05 10 e3 00 00 	mov    rax,QWORD PTR [rip+0xe310]        # 140010218 <__imp_GetLastError>
   140001f08:	ff d0                	call   rax
   140001f0a:	89 c2                	mov    edx,eax
   140001f0c:	48 8d 05 55 93 00 00 	lea    rax,[rip+0x9355]        # 14000b268 <.rdata+0x78>
   140001f13:	48 89 c1             	mov    rcx,rax
   140001f16:	e8 d5 fc ff ff       	call   140001bf0 <__report_error>
   140001f1b:	8b 05 c7 d1 00 00    	mov    eax,DWORD PTR [rip+0xd1c7]        # 14000f0e8 <maxSections>
   140001f21:	83 c0 01             	add    eax,0x1
   140001f24:	89 05 be d1 00 00    	mov    DWORD PTR [rip+0xd1be],eax        # 14000f0e8 <maxSections>
   140001f2a:	eb 01                	jmp    140001f2d <mark_section_writable+0x2d8>
   140001f2c:	90                   	nop
   140001f2d:	48 83 c4 60          	add    rsp,0x60
   140001f31:	5d                   	pop    rbp
   140001f32:	c3                   	ret

0000000140001f33 <restore_modified_sections>:
   140001f33:	55                   	push   rbp
   140001f34:	48 89 e5             	mov    rbp,rsp
   140001f37:	48 83 ec 30          	sub    rsp,0x30
   140001f3b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140001f42:	e9 ad 00 00 00       	jmp    140001ff4 <restore_modified_sections+0xc1>
   140001f47:	48 8b 0d 92 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd192]        # 14000f0e0 <the_secs>
   140001f4e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f51:	48 63 d0             	movsxd rdx,eax
   140001f54:	48 89 d0             	mov    rax,rdx
   140001f57:	48 c1 e0 02          	shl    rax,0x2
   140001f5b:	48 01 d0             	add    rax,rdx
   140001f5e:	48 c1 e0 03          	shl    rax,0x3
   140001f62:	48 01 c8             	add    rax,rcx
   140001f65:	8b 00                	mov    eax,DWORD PTR [rax]
   140001f67:	85 c0                	test   eax,eax
   140001f69:	0f 84 80 00 00 00    	je     140001fef <restore_modified_sections+0xbc>
   140001f6f:	48 8b 0d 6a d1 00 00 	mov    rcx,QWORD PTR [rip+0xd16a]        # 14000f0e0 <the_secs>
   140001f76:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f79:	48 63 d0             	movsxd rdx,eax
   140001f7c:	48 89 d0             	mov    rax,rdx
   140001f7f:	48 c1 e0 02          	shl    rax,0x2
   140001f83:	48 01 d0             	add    rax,rdx
   140001f86:	48 c1 e0 03          	shl    rax,0x3
   140001f8a:	48 01 c8             	add    rax,rcx
   140001f8d:	44 8b 10             	mov    r10d,DWORD PTR [rax]
   140001f90:	48 8b 0d 49 d1 00 00 	mov    rcx,QWORD PTR [rip+0xd149]        # 14000f0e0 <the_secs>
   140001f97:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001f9a:	48 63 d0             	movsxd rdx,eax
   140001f9d:	48 89 d0             	mov    rax,rdx
   140001fa0:	48 c1 e0 02          	shl    rax,0x2
   140001fa4:	48 01 d0             	add    rax,rdx
   140001fa7:	48 c1 e0 03          	shl    rax,0x3
   140001fab:	48 01 c8             	add    rax,rcx
   140001fae:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
   140001fb2:	4c 8b 05 27 d1 00 00 	mov    r8,QWORD PTR [rip+0xd127]        # 14000f0e0 <the_secs>
   140001fb9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140001fbc:	48 63 d0             	movsxd rdx,eax
   140001fbf:	48 89 d0             	mov    rax,rdx
   140001fc2:	48 c1 e0 02          	shl    rax,0x2
   140001fc6:	48 01 d0             	add    rax,rdx
   140001fc9:	48 c1 e0 03          	shl    rax,0x3
   140001fcd:	4c 01 c0             	add    rax,r8
   140001fd0:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
   140001fd4:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   140001fd8:	49 89 d1             	mov    r9,rdx
   140001fdb:	45 89 d0             	mov    r8d,r10d
   140001fde:	48 89 ca             	mov    rdx,rcx
   140001fe1:	48 89 c1             	mov    rcx,rax
   140001fe4:	48 8b 05 7d e2 00 00 	mov    rax,QWORD PTR [rip+0xe27d]        # 140010268 <__imp_VirtualProtect>
   140001feb:	ff d0                	call   rax
   140001fed:	eb 01                	jmp    140001ff0 <restore_modified_sections+0xbd>
   140001fef:	90                   	nop
   140001ff0:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140001ff4:	8b 05 ee d0 00 00    	mov    eax,DWORD PTR [rip+0xd0ee]        # 14000f0e8 <maxSections>
   140001ffa:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140001ffd:	0f 8c 44 ff ff ff    	jl     140001f47 <restore_modified_sections+0x14>
   140002003:	90                   	nop
   140002004:	90                   	nop
   140002005:	48 83 c4 30          	add    rsp,0x30
   140002009:	5d                   	pop    rbp
   14000200a:	c3                   	ret

000000014000200b <__write_memory>:
   14000200b:	55                   	push   rbp
   14000200c:	48 89 e5             	mov    rbp,rsp
   14000200f:	48 83 ec 20          	sub    rsp,0x20
   140002013:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002017:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000201b:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000201f:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140002024:	74 25                	je     14000204b <__write_memory+0x40>
   140002026:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000202a:	48 89 c1             	mov    rcx,rax
   14000202d:	e8 23 fc ff ff       	call   140001c55 <mark_section_writable>
   140002032:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140002036:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000203a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000203e:	49 89 c8             	mov    r8,rcx
   140002041:	48 89 c1             	mov    rcx,rax
   140002044:	e8 df 76 00 00       	call   140009728 <memcpy>
   140002049:	eb 01                	jmp    14000204c <__write_memory+0x41>
   14000204b:	90                   	nop
   14000204c:	48 83 c4 20          	add    rsp,0x20
   140002050:	5d                   	pop    rbp
   140002051:	c3                   	ret

0000000140002052 <do_pseudo_reloc>:
   140002052:	55                   	push   rbp
   140002053:	48 89 e5             	mov    rbp,rsp
   140002056:	48 83 c4 80          	add    rsp,0xffffffffffffff80
   14000205a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000205e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002062:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002066:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000206a:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   14000206e:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002072:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002076:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000207a:	48 83 7d e0 07       	cmp    QWORD PTR [rbp-0x20],0x7
   14000207f:	0f 8e 44 03 00 00    	jle    1400023c9 <do_pseudo_reloc+0x377>
   140002085:	48 83 7d e0 0b       	cmp    QWORD PTR [rbp-0x20],0xb
   14000208a:	7e 25                	jle    1400020b1 <do_pseudo_reloc+0x5f>
   14000208c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002090:	8b 00                	mov    eax,DWORD PTR [rax]
   140002092:	85 c0                	test   eax,eax
   140002094:	75 1b                	jne    1400020b1 <do_pseudo_reloc+0x5f>
   140002096:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000209a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000209d:	85 c0                	test   eax,eax
   14000209f:	75 10                	jne    1400020b1 <do_pseudo_reloc+0x5f>
   1400020a1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020a5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400020a8:	85 c0                	test   eax,eax
   1400020aa:	75 05                	jne    1400020b1 <do_pseudo_reloc+0x5f>
   1400020ac:	48 83 45 f8 0c       	add    QWORD PTR [rbp-0x8],0xc
   1400020b1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020b5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020b7:	85 c0                	test   eax,eax
   1400020b9:	75 0b                	jne    1400020c6 <do_pseudo_reloc+0x74>
   1400020bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020bf:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020c2:	85 c0                	test   eax,eax
   1400020c4:	74 59                	je     14000211f <do_pseudo_reloc+0xcd>
   1400020c6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400020ca:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400020ce:	eb 40                	jmp    140002110 <do_pseudo_reloc+0xbe>
   1400020d0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020d4:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400020d7:	89 c2                	mov    edx,eax
   1400020d9:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400020dd:	48 01 d0             	add    rax,rdx
   1400020e0:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400020e4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020e8:	8b 10                	mov    edx,DWORD PTR [rax]
   1400020ea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400020ee:	8b 00                	mov    eax,DWORD PTR [rax]
   1400020f0:	01 d0                	add    eax,edx
   1400020f2:	89 45 b4             	mov    DWORD PTR [rbp-0x4c],eax
   1400020f5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400020f9:	48 8d 55 b4          	lea    rdx,[rbp-0x4c]
   1400020fd:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002103:	48 89 c1             	mov    rcx,rax
   140002106:	e8 00 ff ff ff       	call   14000200b <__write_memory>
   14000210b:	48 83 45 e8 08       	add    QWORD PTR [rbp-0x18],0x8
   140002110:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002114:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140002118:	72 b6                	jb     1400020d0 <do_pseudo_reloc+0x7e>
   14000211a:	e9 ab 02 00 00       	jmp    1400023ca <do_pseudo_reloc+0x378>
   14000211f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002123:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002126:	83 f8 01             	cmp    eax,0x1
   140002129:	74 18                	je     140002143 <do_pseudo_reloc+0xf1>
   14000212b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000212f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002132:	89 c2                	mov    edx,eax
   140002134:	48 8d 05 55 91 00 00 	lea    rax,[rip+0x9155]        # 14000b290 <.rdata+0xa0>
   14000213b:	48 89 c1             	mov    rcx,rax
   14000213e:	e8 ad fa ff ff       	call   140001bf0 <__report_error>
   140002143:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002147:	48 83 c0 0c          	add    rax,0xc
   14000214b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000214f:	e9 65 02 00 00       	jmp    1400023b9 <do_pseudo_reloc+0x367>
   140002154:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002158:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000215b:	89 c2                	mov    edx,eax
   14000215d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002161:	48 01 d0             	add    rax,rdx
   140002164:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002168:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000216c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000216e:	89 c2                	mov    edx,eax
   140002170:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002174:	48 01 d0             	add    rax,rdx
   140002177:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000217b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000217f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002182:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140002186:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000218a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000218d:	0f b6 c0             	movzx  eax,al
   140002190:	83 f8 40             	cmp    eax,0x40
   140002193:	0f 84 b6 00 00 00    	je     14000224f <do_pseudo_reloc+0x1fd>
   140002199:	83 f8 40             	cmp    eax,0x40
   14000219c:	0f 87 ba 00 00 00    	ja     14000225c <do_pseudo_reloc+0x20a>
   1400021a2:	83 f8 20             	cmp    eax,0x20
   1400021a5:	74 77                	je     14000221e <do_pseudo_reloc+0x1cc>
   1400021a7:	83 f8 20             	cmp    eax,0x20
   1400021aa:	0f 87 ac 00 00 00    	ja     14000225c <do_pseudo_reloc+0x20a>
   1400021b0:	83 f8 08             	cmp    eax,0x8
   1400021b3:	74 0a                	je     1400021bf <do_pseudo_reloc+0x16d>
   1400021b5:	83 f8 10             	cmp    eax,0x10
   1400021b8:	74 38                	je     1400021f2 <do_pseudo_reloc+0x1a0>
   1400021ba:	e9 9d 00 00 00       	jmp    14000225c <do_pseudo_reloc+0x20a>
   1400021bf:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021c3:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400021c6:	0f b6 c0             	movzx  eax,al
   1400021c9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021cd:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021d1:	25 80 00 00 00       	and    eax,0x80
   1400021d6:	48 85 c0             	test   rax,rax
   1400021d9:	0f 84 9d 00 00 00    	je     14000227c <do_pseudo_reloc+0x22a>
   1400021df:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400021e3:	48 0d 00 ff ff ff    	or     rax,0xffffffffffffff00
   1400021e9:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400021ed:	e9 8a 00 00 00       	jmp    14000227c <do_pseudo_reloc+0x22a>
   1400021f2:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400021f6:	0f b7 00             	movzx  eax,WORD PTR [rax]
   1400021f9:	0f b7 c0             	movzx  eax,ax
   1400021fc:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140002200:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002204:	25 00 80 00 00       	and    eax,0x8000
   140002209:	48 85 c0             	test   rax,rax
   14000220c:	74 71                	je     14000227f <do_pseudo_reloc+0x22d>
   14000220e:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002212:	48 0d 00 00 ff ff    	or     rax,0xffffffffffff0000
   140002218:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000221c:	eb 61                	jmp    14000227f <do_pseudo_reloc+0x22d>
   14000221e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002222:	8b 00                	mov    eax,DWORD PTR [rax]
   140002224:	89 c0                	mov    eax,eax
   140002226:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000222a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000222e:	25 00 00 00 80       	and    eax,0x80000000
   140002233:	48 85 c0             	test   rax,rax
   140002236:	74 4a                	je     140002282 <do_pseudo_reloc+0x230>
   140002238:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000223c:	48 ba 00 00 00 00 ff 	movabs rdx,0xffffffff00000000
   140002243:	ff ff ff 
   140002246:	48 09 d0             	or     rax,rdx
   140002249:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000224d:	eb 33                	jmp    140002282 <do_pseudo_reloc+0x230>
   14000224f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002253:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140002256:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000225a:	eb 27                	jmp    140002283 <do_pseudo_reloc+0x231>
   14000225c:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
   140002263:	00 
   140002264:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002268:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000226b:	0f b6 c0             	movzx  eax,al
   14000226e:	48 8d 0d 53 90 00 00 	lea    rcx,[rip+0x9053]        # 14000b2c8 <.rdata+0xd8>
   140002275:	89 c2                	mov    edx,eax
   140002277:	e8 74 f9 ff ff       	call   140001bf0 <__report_error>
   14000227c:	90                   	nop
   14000227d:	eb 04                	jmp    140002283 <do_pseudo_reloc+0x231>
   14000227f:	90                   	nop
   140002280:	eb 01                	jmp    140002283 <do_pseudo_reloc+0x231>
   140002282:	90                   	nop
   140002283:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
   140002287:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000228b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000228d:	89 c2                	mov    edx,eax
   14000228f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140002293:	48 01 c2             	add    rdx,rax
   140002296:	48 89 c8             	mov    rax,rcx
   140002299:	48 29 d0             	sub    rax,rdx
   14000229c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022a0:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   1400022a4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400022a8:	48 01 d0             	add    rax,rdx
   1400022ab:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400022af:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400022b3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400022b6:	25 ff 00 00 00       	and    eax,0xff
   1400022bb:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400022be:	83 7d d4 3f          	cmp    DWORD PTR [rbp-0x2c],0x3f
   1400022c2:	77 67                	ja     14000232b <do_pseudo_reloc+0x2d9>
   1400022c4:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022c7:	ba 01 00 00 00       	mov    edx,0x1
   1400022cc:	89 c1                	mov    ecx,eax
   1400022ce:	48 d3 e2             	shl    rdx,cl
   1400022d1:	48 89 d0             	mov    rax,rdx
   1400022d4:	48 83 e8 01          	sub    rax,0x1
   1400022d8:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400022dc:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   1400022df:	83 e8 01             	sub    eax,0x1
   1400022e2:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
   1400022e9:	89 c1                	mov    ecx,eax
   1400022eb:	48 d3 e2             	shl    rdx,cl
   1400022ee:	48 89 d0             	mov    rax,rdx
   1400022f1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400022f5:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400022f9:	48 39 45 c8          	cmp    QWORD PTR [rbp-0x38],rax
   1400022fd:	7c 0a                	jl     140002309 <do_pseudo_reloc+0x2b7>
   1400022ff:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140002303:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   140002307:	7e 22                	jle    14000232b <do_pseudo_reloc+0x2d9>
   140002309:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   14000230d:	4c 8b 4d d8          	mov    r9,QWORD PTR [rbp-0x28]
   140002311:	4c 8b 45 e0          	mov    r8,QWORD PTR [rbp-0x20]
   140002315:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140002318:	48 8d 0d d9 8f 00 00 	lea    rcx,[rip+0x8fd9]        # 14000b2f8 <.rdata+0x108>
   14000231f:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140002324:	89 c2                	mov    edx,eax
   140002326:	e8 c5 f8 ff ff       	call   140001bf0 <__report_error>
   14000232b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000232f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002332:	0f b6 c0             	movzx  eax,al
   140002335:	83 f8 40             	cmp    eax,0x40
   140002338:	74 63                	je     14000239d <do_pseudo_reloc+0x34b>
   14000233a:	83 f8 40             	cmp    eax,0x40
   14000233d:	77 75                	ja     1400023b4 <do_pseudo_reloc+0x362>
   14000233f:	83 f8 20             	cmp    eax,0x20
   140002342:	74 41                	je     140002385 <do_pseudo_reloc+0x333>
   140002344:	83 f8 20             	cmp    eax,0x20
   140002347:	77 6b                	ja     1400023b4 <do_pseudo_reloc+0x362>
   140002349:	83 f8 08             	cmp    eax,0x8
   14000234c:	74 07                	je     140002355 <do_pseudo_reloc+0x303>
   14000234e:	83 f8 10             	cmp    eax,0x10
   140002351:	74 1a                	je     14000236d <do_pseudo_reloc+0x31b>
   140002353:	eb 5f                	jmp    1400023b4 <do_pseudo_reloc+0x362>
   140002355:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002359:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000235d:	41 b8 01 00 00 00    	mov    r8d,0x1
   140002363:	48 89 c1             	mov    rcx,rax
   140002366:	e8 a0 fc ff ff       	call   14000200b <__write_memory>
   14000236b:	eb 47                	jmp    1400023b4 <do_pseudo_reloc+0x362>
   14000236d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002371:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   140002375:	41 b8 02 00 00 00    	mov    r8d,0x2
   14000237b:	48 89 c1             	mov    rcx,rax
   14000237e:	e8 88 fc ff ff       	call   14000200b <__write_memory>
   140002383:	eb 2f                	jmp    1400023b4 <do_pseudo_reloc+0x362>
   140002385:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002389:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   14000238d:	41 b8 04 00 00 00    	mov    r8d,0x4
   140002393:	48 89 c1             	mov    rcx,rax
   140002396:	e8 70 fc ff ff       	call   14000200b <__write_memory>
   14000239b:	eb 17                	jmp    1400023b4 <do_pseudo_reloc+0x362>
   14000239d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400023a1:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
   1400023a5:	41 b8 08 00 00 00    	mov    r8d,0x8
   1400023ab:	48 89 c1             	mov    rcx,rax
   1400023ae:	e8 58 fc ff ff       	call   14000200b <__write_memory>
   1400023b3:	90                   	nop
   1400023b4:	48 83 45 f0 0c       	add    QWORD PTR [rbp-0x10],0xc
   1400023b9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400023bd:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400023c1:	0f 82 8d fd ff ff    	jb     140002154 <do_pseudo_reloc+0x102>
   1400023c7:	eb 01                	jmp    1400023ca <do_pseudo_reloc+0x378>
   1400023c9:	90                   	nop
   1400023ca:	48 83 ec 80          	sub    rsp,0xffffffffffffff80
   1400023ce:	5d                   	pop    rbp
   1400023cf:	c3                   	ret

00000001400023d0 <_pei386_runtime_relocator>:
   1400023d0:	55                   	push   rbp
   1400023d1:	48 89 e5             	mov    rbp,rsp
   1400023d4:	48 83 ec 30          	sub    rsp,0x30
   1400023d8:	8b 05 0e cd 00 00    	mov    eax,DWORD PTR [rip+0xcd0e]        # 14000f0ec <was_init.0>
   1400023de:	85 c0                	test   eax,eax
   1400023e0:	0f 85 88 00 00 00    	jne    14000246e <_pei386_runtime_relocator+0x9e>
   1400023e6:	8b 05 00 cd 00 00    	mov    eax,DWORD PTR [rip+0xcd00]        # 14000f0ec <was_init.0>
   1400023ec:	83 c0 01             	add    eax,0x1
   1400023ef:	89 05 f7 cc 00 00    	mov    DWORD PTR [rip+0xccf7],eax        # 14000f0ec <was_init.0>
   1400023f5:	e8 21 0b 00 00       	call   140002f1b <__mingw_GetSectionCount>
   1400023fa:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400023fd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002400:	48 63 d0             	movsxd rdx,eax
   140002403:	48 89 d0             	mov    rax,rdx
   140002406:	48 c1 e0 02          	shl    rax,0x2
   14000240a:	48 01 d0             	add    rax,rdx
   14000240d:	48 c1 e0 03          	shl    rax,0x3
   140002411:	48 83 c0 0f          	add    rax,0xf
   140002415:	48 c1 e8 04          	shr    rax,0x4
   140002419:	48 c1 e0 04          	shl    rax,0x4
   14000241d:	e8 7e 0d 00 00       	call   1400031a0 <___chkstk_ms>
   140002422:	48 29 c4             	sub    rsp,rax
   140002425:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000242a:	48 83 c0 0f          	add    rax,0xf
   14000242e:	48 c1 e8 04          	shr    rax,0x4
   140002432:	48 c1 e0 04          	shl    rax,0x4
   140002436:	48 89 05 a3 cc 00 00 	mov    QWORD PTR [rip+0xcca3],rax        # 14000f0e0 <the_secs>
   14000243d:	c7 05 a1 cc 00 00 00 	mov    DWORD PTR [rip+0xcca1],0x0        # 14000f0e8 <maxSections>
   140002444:	00 00 00 
   140002447:	48 8b 0d 52 91 00 00 	mov    rcx,QWORD PTR [rip+0x9152]        # 14000b5a0 <.refptr.__ImageBase>
   14000244e:	48 8b 15 5b 91 00 00 	mov    rdx,QWORD PTR [rip+0x915b]        # 14000b5b0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST_END__>
   140002455:	48 8b 05 64 91 00 00 	mov    rax,QWORD PTR [rip+0x9164]        # 14000b5c0 <.refptr.__RUNTIME_PSEUDO_RELOC_LIST__>
   14000245c:	49 89 c8             	mov    r8,rcx
   14000245f:	48 89 c1             	mov    rcx,rax
   140002462:	e8 eb fb ff ff       	call   140002052 <do_pseudo_reloc>
   140002467:	e8 c7 fa ff ff       	call   140001f33 <restore_modified_sections>
   14000246c:	eb 01                	jmp    14000246f <_pei386_runtime_relocator+0x9f>
   14000246e:	90                   	nop
   14000246f:	48 89 ec             	mov    rsp,rbp
   140002472:	5d                   	pop    rbp
   140002473:	c3                   	ret
   140002474:	90                   	nop
   140002475:	90                   	nop
   140002476:	90                   	nop
   140002477:	90                   	nop
   140002478:	90                   	nop
   140002479:	90                   	nop
   14000247a:	90                   	nop
   14000247b:	90                   	nop
   14000247c:	90                   	nop
   14000247d:	90                   	nop
   14000247e:	90                   	nop
   14000247f:	90                   	nop

0000000140002480 <__mingw_raise_matherr>:
   140002480:	55                   	push   rbp
   140002481:	48 89 e5             	mov    rbp,rsp
   140002484:	48 83 ec 50          	sub    rsp,0x50
   140002488:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000248b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000248f:	f2 0f 11 55 20       	movsd  QWORD PTR [rbp+0x20],xmm2
   140002494:	f2 0f 11 5d 28       	movsd  QWORD PTR [rbp+0x28],xmm3
   140002499:	48 8b 05 50 cc 00 00 	mov    rax,QWORD PTR [rip+0xcc50]        # 14000f0f0 <stUserMathErr>
   1400024a0:	48 85 c0             	test   rax,rax
   1400024a3:	74 3e                	je     1400024e3 <__mingw_raise_matherr+0x63>
   1400024a5:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400024a8:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   1400024ab:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400024af:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400024b3:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   1400024b8:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   1400024bd:	f2 0f 10 45 28       	movsd  xmm0,QWORD PTR [rbp+0x28]
   1400024c2:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
   1400024c7:	f2 0f 10 45 30       	movsd  xmm0,QWORD PTR [rbp+0x30]
   1400024cc:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   1400024d1:	48 8b 15 18 cc 00 00 	mov    rdx,QWORD PTR [rip+0xcc18]        # 14000f0f0 <stUserMathErr>
   1400024d8:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400024dc:	48 89 c1             	mov    rcx,rax
   1400024df:	ff d2                	call   rdx
   1400024e1:	eb 01                	jmp    1400024e4 <__mingw_raise_matherr+0x64>
   1400024e3:	90                   	nop
   1400024e4:	48 83 c4 50          	add    rsp,0x50
   1400024e8:	5d                   	pop    rbp
   1400024e9:	c3                   	ret

00000001400024ea <__mingw_setusermatherr>:
   1400024ea:	55                   	push   rbp
   1400024eb:	48 89 e5             	mov    rbp,rsp
   1400024ee:	48 83 ec 20          	sub    rsp,0x20
   1400024f2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400024f6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400024fa:	48 89 05 ef cb 00 00 	mov    QWORD PTR [rip+0xcbef],rax        # 14000f0f0 <stUserMathErr>
   140002501:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002505:	48 89 c1             	mov    rcx,rax
   140002508:	e8 93 71 00 00       	call   1400096a0 <__setusermatherr>
   14000250d:	90                   	nop
   14000250e:	48 83 c4 20          	add    rsp,0x20
   140002512:	5d                   	pop    rbp
   140002513:	c3                   	ret
   140002514:	90                   	nop
   140002515:	90                   	nop
   140002516:	90                   	nop
   140002517:	90                   	nop
   140002518:	90                   	nop
   140002519:	90                   	nop
   14000251a:	90                   	nop
   14000251b:	90                   	nop
   14000251c:	90                   	nop
   14000251d:	90                   	nop
   14000251e:	90                   	nop
   14000251f:	90                   	nop

0000000140002520 <__mingw_SEH_error_handler>:
   140002520:	55                   	push   rbp
   140002521:	48 89 e5             	mov    rbp,rsp
   140002524:	48 83 ec 30          	sub    rsp,0x30
   140002528:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000252c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002530:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002534:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140002538:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   14000253f:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002546:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000254a:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000254d:	83 e0 02             	and    eax,0x2
   140002550:	85 c0                	test   eax,eax
   140002552:	74 0a                	je     14000255e <__mingw_SEH_error_handler+0x3e>
   140002554:	b8 01 00 00 00       	mov    eax,0x1
   140002559:	e9 16 02 00 00       	jmp    140002774 <__mingw_SEH_error_handler+0x254>
   14000255e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002562:	8b 00                	mov    eax,DWORD PTR [rax]
   140002564:	25 ff ff ff 20       	and    eax,0x20ffffff
   140002569:	3d 43 43 47 20       	cmp    eax,0x20474343
   14000256e:	75 18                	jne    140002588 <__mingw_SEH_error_handler+0x68>
   140002570:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002574:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140002577:	83 e0 01             	and    eax,0x1
   14000257a:	85 c0                	test   eax,eax
   14000257c:	75 0a                	jne    140002588 <__mingw_SEH_error_handler+0x68>
   14000257e:	b8 00 00 00 00       	mov    eax,0x0
   140002583:	e9 ec 01 00 00       	jmp    140002774 <__mingw_SEH_error_handler+0x254>
   140002588:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000258c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000258e:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   140002593:	0f 84 12 01 00 00    	je     1400026ab <__mingw_SEH_error_handler+0x18b>
   140002599:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   14000259e:	0f 87 c3 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   1400025a4:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400025a9:	0f 87 b8 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   1400025af:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400025b4:	0f 83 4c 01 00 00    	jae    140002706 <__mingw_SEH_error_handler+0x1e6>
   1400025ba:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400025bf:	0f 84 3a 01 00 00    	je     1400026ff <__mingw_SEH_error_handler+0x1df>
   1400025c5:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400025ca:	0f 87 97 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   1400025d0:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025d5:	0f 84 83 01 00 00    	je     14000275e <__mingw_SEH_error_handler+0x23e>
   1400025db:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   1400025e0:	0f 87 81 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   1400025e6:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   1400025eb:	0f 87 76 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   1400025f1:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   1400025f6:	0f 83 03 01 00 00    	jae    1400026ff <__mingw_SEH_error_handler+0x1df>
   1400025fc:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002601:	0f 84 57 01 00 00    	je     14000275e <__mingw_SEH_error_handler+0x23e>
   140002607:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000260c:	0f 87 55 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   140002612:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002617:	0f 84 8e 00 00 00    	je     1400026ab <__mingw_SEH_error_handler+0x18b>
   14000261d:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002622:	0f 87 3f 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   140002628:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000262d:	0f 84 2b 01 00 00    	je     14000275e <__mingw_SEH_error_handler+0x23e>
   140002633:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002638:	0f 87 29 01 00 00    	ja     140002767 <__mingw_SEH_error_handler+0x247>
   14000263e:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002643:	0f 84 15 01 00 00    	je     14000275e <__mingw_SEH_error_handler+0x23e>
   140002649:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000264e:	0f 85 13 01 00 00    	jne    140002767 <__mingw_SEH_error_handler+0x247>
   140002654:	ba 00 00 00 00       	mov    edx,0x0
   140002659:	b9 0b 00 00 00       	mov    ecx,0xb
   14000265e:	e8 e5 70 00 00       	call   140009748 <signal>
   140002663:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002667:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000266c:	75 1b                	jne    140002689 <__mingw_SEH_error_handler+0x169>
   14000266e:	ba 01 00 00 00       	mov    edx,0x1
   140002673:	b9 0b 00 00 00       	mov    ecx,0xb
   140002678:	e8 cb 70 00 00       	call   140009748 <signal>
   14000267d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002684:	e9 e1 00 00 00       	jmp    14000276a <__mingw_SEH_error_handler+0x24a>
   140002689:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000268e:	0f 84 d6 00 00 00    	je     14000276a <__mingw_SEH_error_handler+0x24a>
   140002694:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002698:	b9 0b 00 00 00       	mov    ecx,0xb
   14000269d:	ff d0                	call   rax
   14000269f:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026a6:	e9 bf 00 00 00       	jmp    14000276a <__mingw_SEH_error_handler+0x24a>
   1400026ab:	ba 00 00 00 00       	mov    edx,0x0
   1400026b0:	b9 04 00 00 00       	mov    ecx,0x4
   1400026b5:	e8 8e 70 00 00       	call   140009748 <signal>
   1400026ba:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400026be:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400026c3:	75 1b                	jne    1400026e0 <__mingw_SEH_error_handler+0x1c0>
   1400026c5:	ba 01 00 00 00       	mov    edx,0x1
   1400026ca:	b9 04 00 00 00       	mov    ecx,0x4
   1400026cf:	e8 74 70 00 00       	call   140009748 <signal>
   1400026d4:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026db:	e9 8d 00 00 00       	jmp    14000276d <__mingw_SEH_error_handler+0x24d>
   1400026e0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400026e5:	0f 84 82 00 00 00    	je     14000276d <__mingw_SEH_error_handler+0x24d>
   1400026eb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400026ef:	b9 04 00 00 00       	mov    ecx,0x4
   1400026f4:	ff d0                	call   rax
   1400026f6:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400026fd:	eb 6e                	jmp    14000276d <__mingw_SEH_error_handler+0x24d>
   1400026ff:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002706:	ba 00 00 00 00       	mov    edx,0x0
   14000270b:	b9 08 00 00 00       	mov    ecx,0x8
   140002710:	e8 33 70 00 00       	call   140009748 <signal>
   140002715:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002719:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000271e:	75 23                	jne    140002743 <__mingw_SEH_error_handler+0x223>
   140002720:	ba 01 00 00 00       	mov    edx,0x1
   140002725:	b9 08 00 00 00       	mov    ecx,0x8
   14000272a:	e8 19 70 00 00       	call   140009748 <signal>
   14000272f:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002733:	74 05                	je     14000273a <__mingw_SEH_error_handler+0x21a>
   140002735:	e8 a6 05 00 00       	call   140002ce0 <_fpreset>
   14000273a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002741:	eb 2d                	jmp    140002770 <__mingw_SEH_error_handler+0x250>
   140002743:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002748:	74 26                	je     140002770 <__mingw_SEH_error_handler+0x250>
   14000274a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000274e:	b9 08 00 00 00       	mov    ecx,0x8
   140002753:	ff d0                	call   rax
   140002755:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000275c:	eb 12                	jmp    140002770 <__mingw_SEH_error_handler+0x250>
   14000275e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140002765:	eb 0a                	jmp    140002771 <__mingw_SEH_error_handler+0x251>
   140002767:	90                   	nop
   140002768:	eb 07                	jmp    140002771 <__mingw_SEH_error_handler+0x251>
   14000276a:	90                   	nop
   14000276b:	eb 04                	jmp    140002771 <__mingw_SEH_error_handler+0x251>
   14000276d:	90                   	nop
   14000276e:	eb 01                	jmp    140002771 <__mingw_SEH_error_handler+0x251>
   140002770:	90                   	nop
   140002771:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140002774:	48 83 c4 30          	add    rsp,0x30
   140002778:	5d                   	pop    rbp
   140002779:	c3                   	ret

000000014000277a <_gnu_exception_handler>:
   14000277a:	55                   	push   rbp
   14000277b:	48 89 e5             	mov    rbp,rsp
   14000277e:	48 83 ec 30          	sub    rsp,0x30
   140002782:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002786:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000278d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140002794:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002798:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000279b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000279d:	25 ff ff ff 20       	and    eax,0x20ffffff
   1400027a2:	3d 43 43 47 20       	cmp    eax,0x20474343
   1400027a7:	75 1b                	jne    1400027c4 <_gnu_exception_handler+0x4a>
   1400027a9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400027ad:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027b0:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   1400027b3:	83 e0 01             	and    eax,0x1
   1400027b6:	85 c0                	test   eax,eax
   1400027b8:	75 0a                	jne    1400027c4 <_gnu_exception_handler+0x4a>
   1400027ba:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400027bf:	e9 14 02 00 00       	jmp    1400029d8 <_gnu_exception_handler+0x25e>
   1400027c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400027c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400027cb:	8b 00                	mov    eax,DWORD PTR [rax]
   1400027cd:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027d2:	0f 84 12 01 00 00    	je     1400028ea <_gnu_exception_handler+0x170>
   1400027d8:	3d 96 00 00 c0       	cmp    eax,0xc0000096
   1400027dd:	0f 87 c3 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   1400027e3:	3d 95 00 00 c0       	cmp    eax,0xc0000095
   1400027e8:	0f 87 b8 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   1400027ee:	3d 94 00 00 c0       	cmp    eax,0xc0000094
   1400027f3:	0f 83 4c 01 00 00    	jae    140002945 <_gnu_exception_handler+0x1cb>
   1400027f9:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   1400027fe:	0f 84 3a 01 00 00    	je     14000293e <_gnu_exception_handler+0x1c4>
   140002804:	3d 93 00 00 c0       	cmp    eax,0xc0000093
   140002809:	0f 87 97 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   14000280f:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   140002814:	0f 84 83 01 00 00    	je     14000299d <_gnu_exception_handler+0x223>
   14000281a:	3d 92 00 00 c0       	cmp    eax,0xc0000092
   14000281f:	0f 87 81 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   140002825:	3d 91 00 00 c0       	cmp    eax,0xc0000091
   14000282a:	0f 87 76 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   140002830:	3d 8d 00 00 c0       	cmp    eax,0xc000008d
   140002835:	0f 83 03 01 00 00    	jae    14000293e <_gnu_exception_handler+0x1c4>
   14000283b:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   140002840:	0f 84 57 01 00 00    	je     14000299d <_gnu_exception_handler+0x223>
   140002846:	3d 8c 00 00 c0       	cmp    eax,0xc000008c
   14000284b:	0f 87 55 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   140002851:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002856:	0f 84 8e 00 00 00    	je     1400028ea <_gnu_exception_handler+0x170>
   14000285c:	3d 1d 00 00 c0       	cmp    eax,0xc000001d
   140002861:	0f 87 3f 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   140002867:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   14000286c:	0f 84 2b 01 00 00    	je     14000299d <_gnu_exception_handler+0x223>
   140002872:	3d 08 00 00 c0       	cmp    eax,0xc0000008
   140002877:	0f 87 29 01 00 00    	ja     1400029a6 <_gnu_exception_handler+0x22c>
   14000287d:	3d 02 00 00 80       	cmp    eax,0x80000002
   140002882:	0f 84 15 01 00 00    	je     14000299d <_gnu_exception_handler+0x223>
   140002888:	3d 05 00 00 c0       	cmp    eax,0xc0000005
   14000288d:	0f 85 13 01 00 00    	jne    1400029a6 <_gnu_exception_handler+0x22c>
   140002893:	ba 00 00 00 00       	mov    edx,0x0
   140002898:	b9 0b 00 00 00       	mov    ecx,0xb
   14000289d:	e8 a6 6e 00 00       	call   140009748 <signal>
   1400028a2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028a6:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   1400028ab:	75 1b                	jne    1400028c8 <_gnu_exception_handler+0x14e>
   1400028ad:	ba 01 00 00 00       	mov    edx,0x1
   1400028b2:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028b7:	e8 8c 6e 00 00       	call   140009748 <signal>
   1400028bc:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028c3:	e9 e1 00 00 00       	jmp    1400029a9 <_gnu_exception_handler+0x22f>
   1400028c8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400028cd:	0f 84 d6 00 00 00    	je     1400029a9 <_gnu_exception_handler+0x22f>
   1400028d3:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400028d7:	b9 0b 00 00 00       	mov    ecx,0xb
   1400028dc:	ff d0                	call   rax
   1400028de:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400028e5:	e9 bf 00 00 00       	jmp    1400029a9 <_gnu_exception_handler+0x22f>
   1400028ea:	ba 00 00 00 00       	mov    edx,0x0
   1400028ef:	b9 04 00 00 00       	mov    ecx,0x4
   1400028f4:	e8 4f 6e 00 00       	call   140009748 <signal>
   1400028f9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400028fd:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   140002902:	75 1b                	jne    14000291f <_gnu_exception_handler+0x1a5>
   140002904:	ba 01 00 00 00       	mov    edx,0x1
   140002909:	b9 04 00 00 00       	mov    ecx,0x4
   14000290e:	e8 35 6e 00 00       	call   140009748 <signal>
   140002913:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000291a:	e9 8d 00 00 00       	jmp    1400029ac <_gnu_exception_handler+0x232>
   14000291f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002924:	0f 84 82 00 00 00    	je     1400029ac <_gnu_exception_handler+0x232>
   14000292a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000292e:	b9 04 00 00 00       	mov    ecx,0x4
   140002933:	ff d0                	call   rax
   140002935:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000293c:	eb 6e                	jmp    1400029ac <_gnu_exception_handler+0x232>
   14000293e:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140002945:	ba 00 00 00 00       	mov    edx,0x0
   14000294a:	b9 08 00 00 00       	mov    ecx,0x8
   14000294f:	e8 f4 6d 00 00       	call   140009748 <signal>
   140002954:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002958:	48 83 7d f0 01       	cmp    QWORD PTR [rbp-0x10],0x1
   14000295d:	75 23                	jne    140002982 <_gnu_exception_handler+0x208>
   14000295f:	ba 01 00 00 00       	mov    edx,0x1
   140002964:	b9 08 00 00 00       	mov    ecx,0x8
   140002969:	e8 da 6d 00 00       	call   140009748 <signal>
   14000296e:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140002972:	74 05                	je     140002979 <_gnu_exception_handler+0x1ff>
   140002974:	e8 67 03 00 00       	call   140002ce0 <_fpreset>
   140002979:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   140002980:	eb 2d                	jmp    1400029af <_gnu_exception_handler+0x235>
   140002982:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002987:	74 26                	je     1400029af <_gnu_exception_handler+0x235>
   140002989:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000298d:	b9 08 00 00 00       	mov    ecx,0x8
   140002992:	ff d0                	call   rax
   140002994:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   14000299b:	eb 12                	jmp    1400029af <_gnu_exception_handler+0x235>
   14000299d:	c7 45 fc ff ff ff ff 	mov    DWORD PTR [rbp-0x4],0xffffffff
   1400029a4:	eb 0a                	jmp    1400029b0 <_gnu_exception_handler+0x236>
   1400029a6:	90                   	nop
   1400029a7:	eb 07                	jmp    1400029b0 <_gnu_exception_handler+0x236>
   1400029a9:	90                   	nop
   1400029aa:	eb 04                	jmp    1400029b0 <_gnu_exception_handler+0x236>
   1400029ac:	90                   	nop
   1400029ad:	eb 01                	jmp    1400029b0 <_gnu_exception_handler+0x236>
   1400029af:	90                   	nop
   1400029b0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400029b4:	75 1f                	jne    1400029d5 <_gnu_exception_handler+0x25b>
   1400029b6:	48 8b 05 53 c7 00 00 	mov    rax,QWORD PTR [rip+0xc753]        # 14000f110 <__mingw_oldexcpt_handler>
   1400029bd:	48 85 c0             	test   rax,rax
   1400029c0:	74 13                	je     1400029d5 <_gnu_exception_handler+0x25b>
   1400029c2:	48 8b 15 47 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc747]        # 14000f110 <__mingw_oldexcpt_handler>
   1400029c9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400029cd:	48 89 c1             	mov    rcx,rax
   1400029d0:	ff d2                	call   rdx
   1400029d2:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400029d5:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400029d8:	48 83 c4 30          	add    rsp,0x30
   1400029dc:	5d                   	pop    rbp
   1400029dd:	c3                   	ret
   1400029de:	90                   	nop
   1400029df:	90                   	nop

00000001400029e0 <___w64_mingwthr_add_key_dtor>:
   1400029e0:	55                   	push   rbp
   1400029e1:	48 89 e5             	mov    rbp,rsp
   1400029e4:	48 83 ec 30          	sub    rsp,0x30
   1400029e8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400029eb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400029ef:	8b 05 53 c7 00 00    	mov    eax,DWORD PTR [rip+0xc753]        # 14000f148 <__mingwthr_cs_init>
   1400029f5:	85 c0                	test   eax,eax
   1400029f7:	75 07                	jne    140002a00 <___w64_mingwthr_add_key_dtor+0x20>
   1400029f9:	b8 00 00 00 00       	mov    eax,0x0
   1400029fe:	eb 7b                	jmp    140002a7b <___w64_mingwthr_add_key_dtor+0x9b>
   140002a00:	ba 18 00 00 00       	mov    edx,0x18
   140002a05:	b9 01 00 00 00       	mov    ecx,0x1
   140002a0a:	e8 d9 6c 00 00       	call   1400096e8 <calloc>
   140002a0f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002a13:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002a18:	75 07                	jne    140002a21 <___w64_mingwthr_add_key_dtor+0x41>
   140002a1a:	b8 ff ff ff ff       	mov    eax,0xffffffff
   140002a1f:	eb 5a                	jmp    140002a7b <___w64_mingwthr_add_key_dtor+0x9b>
   140002a21:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a25:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140002a28:	89 10                	mov    DWORD PTR [rax],edx
   140002a2a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a2e:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140002a32:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
   140002a36:	48 8d 05 e3 c6 00 00 	lea    rax,[rip+0xc6e3]        # 14000f120 <__mingwthr_cs>
   140002a3d:	48 89 c1             	mov    rcx,rax
   140002a40:	48 8b 05 b9 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7b9]        # 140010200 <__imp_EnterCriticalSection>
   140002a47:	ff d0                	call   rax
   140002a49:	48 8b 15 00 c7 00 00 	mov    rdx,QWORD PTR [rip+0xc700]        # 14000f150 <key_dtor_list>
   140002a50:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a54:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002a58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002a5c:	48 89 05 ed c6 00 00 	mov    QWORD PTR [rip+0xc6ed],rax        # 14000f150 <key_dtor_list>
   140002a63:	48 8d 05 b6 c6 00 00 	lea    rax,[rip+0xc6b6]        # 14000f120 <__mingwthr_cs>
   140002a6a:	48 89 c1             	mov    rcx,rax
   140002a6d:	48 8b 05 c4 d7 00 00 	mov    rax,QWORD PTR [rip+0xd7c4]        # 140010238 <__imp_LeaveCriticalSection>
   140002a74:	ff d0                	call   rax
   140002a76:	b8 00 00 00 00       	mov    eax,0x0
   140002a7b:	48 83 c4 30          	add    rsp,0x30
   140002a7f:	5d                   	pop    rbp
   140002a80:	c3                   	ret

0000000140002a81 <___w64_mingwthr_remove_key_dtor>:
   140002a81:	55                   	push   rbp
   140002a82:	48 89 e5             	mov    rbp,rsp
   140002a85:	48 83 ec 30          	sub    rsp,0x30
   140002a89:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140002a8c:	8b 05 b6 c6 00 00    	mov    eax,DWORD PTR [rip+0xc6b6]        # 14000f148 <__mingwthr_cs_init>
   140002a92:	85 c0                	test   eax,eax
   140002a94:	75 0a                	jne    140002aa0 <___w64_mingwthr_remove_key_dtor+0x1f>
   140002a96:	b8 00 00 00 00       	mov    eax,0x0
   140002a9b:	e9 9c 00 00 00       	jmp    140002b3c <___w64_mingwthr_remove_key_dtor+0xbb>
   140002aa0:	48 8d 05 79 c6 00 00 	lea    rax,[rip+0xc679]        # 14000f120 <__mingwthr_cs>
   140002aa7:	48 89 c1             	mov    rcx,rax
   140002aaa:	48 8b 05 4f d7 00 00 	mov    rax,QWORD PTR [rip+0xd74f]        # 140010200 <__imp_EnterCriticalSection>
   140002ab1:	ff d0                	call   rax
   140002ab3:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140002aba:	00 
   140002abb:	48 8b 05 8e c6 00 00 	mov    rax,QWORD PTR [rip+0xc68e]        # 14000f150 <key_dtor_list>
   140002ac2:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002ac6:	eb 55                	jmp    140002b1d <___w64_mingwthr_remove_key_dtor+0x9c>
   140002ac8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002acc:	8b 00                	mov    eax,DWORD PTR [rax]
   140002ace:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140002ad1:	75 36                	jne    140002b09 <___w64_mingwthr_remove_key_dtor+0x88>
   140002ad3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002ad8:	75 11                	jne    140002aeb <___w64_mingwthr_remove_key_dtor+0x6a>
   140002ada:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002ade:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002ae2:	48 89 05 67 c6 00 00 	mov    QWORD PTR [rip+0xc667],rax        # 14000f150 <key_dtor_list>
   140002ae9:	eb 10                	jmp    140002afb <___w64_mingwthr_remove_key_dtor+0x7a>
   140002aeb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aef:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
   140002af3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002af7:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
   140002afb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002aff:	48 89 c1             	mov    rcx,rax
   140002b02:	e8 09 6c 00 00       	call   140009710 <free>
   140002b07:	eb 1b                	jmp    140002b24 <___w64_mingwthr_remove_key_dtor+0xa3>
   140002b09:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b0d:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002b15:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002b19:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b1d:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b22:	75 a4                	jne    140002ac8 <___w64_mingwthr_remove_key_dtor+0x47>
   140002b24:	48 8d 05 f5 c5 00 00 	lea    rax,[rip+0xc5f5]        # 14000f120 <__mingwthr_cs>
   140002b2b:	48 89 c1             	mov    rcx,rax
   140002b2e:	48 8b 05 03 d7 00 00 	mov    rax,QWORD PTR [rip+0xd703]        # 140010238 <__imp_LeaveCriticalSection>
   140002b35:	ff d0                	call   rax
   140002b37:	b8 00 00 00 00       	mov    eax,0x0
   140002b3c:	48 83 c4 30          	add    rsp,0x30
   140002b40:	5d                   	pop    rbp
   140002b41:	c3                   	ret

0000000140002b42 <__mingwthr_run_key_dtors>:
   140002b42:	55                   	push   rbp
   140002b43:	48 89 e5             	mov    rbp,rsp
   140002b46:	48 83 ec 30          	sub    rsp,0x30
   140002b4a:	8b 05 f8 c5 00 00    	mov    eax,DWORD PTR [rip+0xc5f8]        # 14000f148 <__mingwthr_cs_init>
   140002b50:	85 c0                	test   eax,eax
   140002b52:	0f 84 82 00 00 00    	je     140002bda <__mingwthr_run_key_dtors+0x98>
   140002b58:	48 8d 05 c1 c5 00 00 	lea    rax,[rip+0xc5c1]        # 14000f120 <__mingwthr_cs>
   140002b5f:	48 89 c1             	mov    rcx,rax
   140002b62:	48 8b 05 97 d6 00 00 	mov    rax,QWORD PTR [rip+0xd697]        # 140010200 <__imp_EnterCriticalSection>
   140002b69:	ff d0                	call   rax
   140002b6b:	48 8b 05 de c5 00 00 	mov    rax,QWORD PTR [rip+0xc5de]        # 14000f150 <key_dtor_list>
   140002b72:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002b76:	eb 46                	jmp    140002bbe <__mingwthr_run_key_dtors+0x7c>
   140002b78:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002b7c:	8b 00                	mov    eax,DWORD PTR [rax]
   140002b7e:	89 c1                	mov    ecx,eax
   140002b80:	48 8b 05 d9 d6 00 00 	mov    rax,QWORD PTR [rip+0xd6d9]        # 140010260 <__imp_TlsGetValue>
   140002b87:	ff d0                	call   rax
   140002b89:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002b8d:	48 8b 05 84 d6 00 00 	mov    rax,QWORD PTR [rip+0xd684]        # 140010218 <__imp_GetLastError>
   140002b94:	ff d0                	call   rax
   140002b96:	85 c0                	test   eax,eax
   140002b98:	75 18                	jne    140002bb2 <__mingwthr_run_key_dtors+0x70>
   140002b9a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140002b9f:	74 11                	je     140002bb2 <__mingwthr_run_key_dtors+0x70>
   140002ba1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ba5:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140002ba9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002bad:	48 89 c1             	mov    rcx,rax
   140002bb0:	ff d2                	call   rdx
   140002bb2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002bb6:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002bba:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002bbe:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002bc3:	75 b3                	jne    140002b78 <__mingwthr_run_key_dtors+0x36>
   140002bc5:	48 8d 05 54 c5 00 00 	lea    rax,[rip+0xc554]        # 14000f120 <__mingwthr_cs>
   140002bcc:	48 89 c1             	mov    rcx,rax
   140002bcf:	48 8b 05 62 d6 00 00 	mov    rax,QWORD PTR [rip+0xd662]        # 140010238 <__imp_LeaveCriticalSection>
   140002bd6:	ff d0                	call   rax
   140002bd8:	eb 01                	jmp    140002bdb <__mingwthr_run_key_dtors+0x99>
   140002bda:	90                   	nop
   140002bdb:	48 83 c4 30          	add    rsp,0x30
   140002bdf:	5d                   	pop    rbp
   140002be0:	c3                   	ret

0000000140002be1 <__mingw_TLScallback>:
   140002be1:	55                   	push   rbp
   140002be2:	48 89 e5             	mov    rbp,rsp
   140002be5:	48 83 ec 30          	sub    rsp,0x30
   140002be9:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002bed:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140002bf0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140002bf4:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002bf8:	0f 84 cc 00 00 00    	je     140002cca <__mingw_TLScallback+0xe9>
   140002bfe:	83 7d 18 03          	cmp    DWORD PTR [rbp+0x18],0x3
   140002c02:	0f 87 ca 00 00 00    	ja     140002cd2 <__mingw_TLScallback+0xf1>
   140002c08:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c0c:	0f 84 b1 00 00 00    	je     140002cc3 <__mingw_TLScallback+0xe2>
   140002c12:	83 7d 18 02          	cmp    DWORD PTR [rbp+0x18],0x2
   140002c16:	0f 87 b6 00 00 00    	ja     140002cd2 <__mingw_TLScallback+0xf1>
   140002c1c:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140002c20:	74 33                	je     140002c55 <__mingw_TLScallback+0x74>
   140002c22:	83 7d 18 01          	cmp    DWORD PTR [rbp+0x18],0x1
   140002c26:	0f 85 a6 00 00 00    	jne    140002cd2 <__mingw_TLScallback+0xf1>
   140002c2c:	8b 05 16 c5 00 00    	mov    eax,DWORD PTR [rip+0xc516]        # 14000f148 <__mingwthr_cs_init>
   140002c32:	85 c0                	test   eax,eax
   140002c34:	75 13                	jne    140002c49 <__mingw_TLScallback+0x68>
   140002c36:	48 8d 05 e3 c4 00 00 	lea    rax,[rip+0xc4e3]        # 14000f120 <__mingwthr_cs>
   140002c3d:	48 89 c1             	mov    rcx,rax
   140002c40:	48 8b 05 e9 d5 00 00 	mov    rax,QWORD PTR [rip+0xd5e9]        # 140010230 <__imp_InitializeCriticalSection>
   140002c47:	ff d0                	call   rax
   140002c49:	c7 05 f5 c4 00 00 01 	mov    DWORD PTR [rip+0xc4f5],0x1        # 14000f148 <__mingwthr_cs_init>
   140002c50:	00 00 00 
   140002c53:	eb 7d                	jmp    140002cd2 <__mingw_TLScallback+0xf1>
   140002c55:	e8 e8 fe ff ff       	call   140002b42 <__mingwthr_run_key_dtors>
   140002c5a:	8b 05 e8 c4 00 00    	mov    eax,DWORD PTR [rip+0xc4e8]        # 14000f148 <__mingwthr_cs_init>
   140002c60:	83 f8 01             	cmp    eax,0x1
   140002c63:	75 6c                	jne    140002cd1 <__mingw_TLScallback+0xf0>
   140002c65:	48 8b 05 e4 c4 00 00 	mov    rax,QWORD PTR [rip+0xc4e4]        # 14000f150 <key_dtor_list>
   140002c6c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c70:	eb 20                	jmp    140002c92 <__mingw_TLScallback+0xb1>
   140002c72:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c76:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
   140002c7a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002c7e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002c82:	48 89 c1             	mov    rcx,rax
   140002c85:	e8 86 6a 00 00       	call   140009710 <free>
   140002c8a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002c8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002c92:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140002c97:	75 d9                	jne    140002c72 <__mingw_TLScallback+0x91>
   140002c99:	48 c7 05 ac c4 00 00 	mov    QWORD PTR [rip+0xc4ac],0x0        # 14000f150 <key_dtor_list>
   140002ca0:	00 00 00 00 
   140002ca4:	c7 05 9a c4 00 00 00 	mov    DWORD PTR [rip+0xc49a],0x0        # 14000f148 <__mingwthr_cs_init>
   140002cab:	00 00 00 
   140002cae:	48 8d 05 6b c4 00 00 	lea    rax,[rip+0xc46b]        # 14000f120 <__mingwthr_cs>
   140002cb5:	48 89 c1             	mov    rcx,rax
   140002cb8:	48 8b 05 39 d5 00 00 	mov    rax,QWORD PTR [rip+0xd539]        # 1400101f8 <__IAT_start__>
   140002cbf:	ff d0                	call   rax
   140002cc1:	eb 0e                	jmp    140002cd1 <__mingw_TLScallback+0xf0>
   140002cc3:	e8 18 00 00 00       	call   140002ce0 <_fpreset>
   140002cc8:	eb 08                	jmp    140002cd2 <__mingw_TLScallback+0xf1>
   140002cca:	e8 73 fe ff ff       	call   140002b42 <__mingwthr_run_key_dtors>
   140002ccf:	eb 01                	jmp    140002cd2 <__mingw_TLScallback+0xf1>
   140002cd1:	90                   	nop
   140002cd2:	b8 01 00 00 00       	mov    eax,0x1
   140002cd7:	48 83 c4 30          	add    rsp,0x30
   140002cdb:	5d                   	pop    rbp
   140002cdc:	c3                   	ret
   140002cdd:	90                   	nop
   140002cde:	90                   	nop
   140002cdf:	90                   	nop

0000000140002ce0 <_fpreset>:
   140002ce0:	55                   	push   rbp
   140002ce1:	48 89 e5             	mov    rbp,rsp
   140002ce4:	db e3                	fninit
   140002ce6:	90                   	nop
   140002ce7:	5d                   	pop    rbp
   140002ce8:	c3                   	ret
   140002ce9:	90                   	nop
   140002cea:	90                   	nop
   140002ceb:	90                   	nop
   140002cec:	90                   	nop
   140002ced:	90                   	nop
   140002cee:	90                   	nop
   140002cef:	90                   	nop

0000000140002cf0 <_ValidateImageBase>:
   140002cf0:	55                   	push   rbp
   140002cf1:	48 89 e5             	mov    rbp,rsp
   140002cf4:	48 83 ec 20          	sub    rsp,0x20
   140002cf8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002cfc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d00:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002d04:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d08:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d0b:	66 3d 4d 5a          	cmp    ax,0x5a4d
   140002d0f:	74 07                	je     140002d18 <_ValidateImageBase+0x28>
   140002d11:	b8 00 00 00 00       	mov    eax,0x0
   140002d16:	eb 4e                	jmp    140002d66 <_ValidateImageBase+0x76>
   140002d18:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d1c:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d1f:	48 63 d0             	movsxd rdx,eax
   140002d22:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002d26:	48 01 d0             	add    rax,rdx
   140002d29:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002d2d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d31:	8b 00                	mov    eax,DWORD PTR [rax]
   140002d33:	3d 50 45 00 00       	cmp    eax,0x4550
   140002d38:	74 07                	je     140002d41 <_ValidateImageBase+0x51>
   140002d3a:	b8 00 00 00 00       	mov    eax,0x0
   140002d3f:	eb 25                	jmp    140002d66 <_ValidateImageBase+0x76>
   140002d41:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002d45:	48 83 c0 18          	add    rax,0x18
   140002d49:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d4d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d51:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140002d54:	66 3d 0b 02          	cmp    ax,0x20b
   140002d58:	74 07                	je     140002d61 <_ValidateImageBase+0x71>
   140002d5a:	b8 00 00 00 00       	mov    eax,0x0
   140002d5f:	eb 05                	jmp    140002d66 <_ValidateImageBase+0x76>
   140002d61:	b8 01 00 00 00       	mov    eax,0x1
   140002d66:	48 83 c4 20          	add    rsp,0x20
   140002d6a:	5d                   	pop    rbp
   140002d6b:	c3                   	ret

0000000140002d6c <_FindPESection>:
   140002d6c:	55                   	push   rbp
   140002d6d:	48 89 e5             	mov    rbp,rsp
   140002d70:	48 83 ec 20          	sub    rsp,0x20
   140002d74:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002d78:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140002d7c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d80:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002d83:	48 63 d0             	movsxd rdx,eax
   140002d86:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002d8a:	48 01 d0             	add    rax,rdx
   140002d8d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002d91:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002d98:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002d9c:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002da0:	0f b7 d0             	movzx  edx,ax
   140002da3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002da7:	48 01 d0             	add    rax,rdx
   140002daa:	48 83 c0 18          	add    rax,0x18
   140002dae:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002db2:	eb 36                	jmp    140002dea <_FindPESection+0x7e>
   140002db4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002db8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140002dbb:	89 c0                	mov    eax,eax
   140002dbd:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002dc1:	72 1e                	jb     140002de1 <_FindPESection+0x75>
   140002dc3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dc7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140002dca:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002dce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140002dd1:	01 d0                	add    eax,edx
   140002dd3:	89 c0                	mov    eax,eax
   140002dd5:	48 39 45 18          	cmp    QWORD PTR [rbp+0x18],rax
   140002dd9:	73 06                	jae    140002de1 <_FindPESection+0x75>
   140002ddb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ddf:	eb 1e                	jmp    140002dff <_FindPESection+0x93>
   140002de1:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002de5:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002dea:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002dee:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002df2:	0f b7 c0             	movzx  eax,ax
   140002df5:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002df8:	72 ba                	jb     140002db4 <_FindPESection+0x48>
   140002dfa:	b8 00 00 00 00       	mov    eax,0x0
   140002dff:	48 83 c4 20          	add    rsp,0x20
   140002e03:	5d                   	pop    rbp
   140002e04:	c3                   	ret

0000000140002e05 <_FindPESectionByName>:
   140002e05:	55                   	push   rbp
   140002e06:	48 89 e5             	mov    rbp,rsp
   140002e09:	48 83 ec 40          	sub    rsp,0x40
   140002e0d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002e11:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002e15:	48 89 c1             	mov    rcx,rax
   140002e18:	e8 3b 69 00 00       	call   140009758 <strlen>
   140002e1d:	48 83 f8 08          	cmp    rax,0x8
   140002e21:	76 0a                	jbe    140002e2d <_FindPESectionByName+0x28>
   140002e23:	b8 00 00 00 00       	mov    eax,0x0
   140002e28:	e9 98 00 00 00       	jmp    140002ec5 <_FindPESectionByName+0xc0>
   140002e2d:	48 8b 05 6c 87 00 00 	mov    rax,QWORD PTR [rip+0x876c]        # 14000b5a0 <.refptr.__ImageBase>
   140002e34:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002e38:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e3c:	48 89 c1             	mov    rcx,rax
   140002e3f:	e8 ac fe ff ff       	call   140002cf0 <_ValidateImageBase>
   140002e44:	85 c0                	test   eax,eax
   140002e46:	75 07                	jne    140002e4f <_FindPESectionByName+0x4a>
   140002e48:	b8 00 00 00 00       	mov    eax,0x0
   140002e4d:	eb 76                	jmp    140002ec5 <_FindPESectionByName+0xc0>
   140002e4f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e53:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002e56:	48 63 d0             	movsxd rdx,eax
   140002e59:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002e5d:	48 01 d0             	add    rax,rdx
   140002e60:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002e64:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002e6b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e6f:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002e73:	0f b7 d0             	movzx  edx,ax
   140002e76:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002e7a:	48 01 d0             	add    rax,rdx
   140002e7d:	48 83 c0 18          	add    rax,0x18
   140002e81:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002e85:	eb 29                	jmp    140002eb0 <_FindPESectionByName+0xab>
   140002e87:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002e8b:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140002e8f:	41 b8 08 00 00 00    	mov    r8d,0x8
   140002e95:	48 89 c1             	mov    rcx,rax
   140002e98:	e8 c3 68 00 00       	call   140009760 <strncmp>
   140002e9d:	85 c0                	test   eax,eax
   140002e9f:	75 06                	jne    140002ea7 <_FindPESectionByName+0xa2>
   140002ea1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ea5:	eb 1e                	jmp    140002ec5 <_FindPESectionByName+0xc0>
   140002ea7:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002eab:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002eb0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002eb4:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002eb8:	0f b7 c0             	movzx  eax,ax
   140002ebb:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140002ebe:	72 c7                	jb     140002e87 <_FindPESectionByName+0x82>
   140002ec0:	b8 00 00 00 00       	mov    eax,0x0
   140002ec5:	48 83 c4 40          	add    rsp,0x40
   140002ec9:	5d                   	pop    rbp
   140002eca:	c3                   	ret

0000000140002ecb <__mingw_GetSectionForAddress>:
   140002ecb:	55                   	push   rbp
   140002ecc:	48 89 e5             	mov    rbp,rsp
   140002ecf:	48 83 ec 30          	sub    rsp,0x30
   140002ed3:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002ed7:	48 8b 05 c2 86 00 00 	mov    rax,QWORD PTR [rip+0x86c2]        # 14000b5a0 <.refptr.__ImageBase>
   140002ede:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002ee2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002ee6:	48 89 c1             	mov    rcx,rax
   140002ee9:	e8 02 fe ff ff       	call   140002cf0 <_ValidateImageBase>
   140002eee:	85 c0                	test   eax,eax
   140002ef0:	75 07                	jne    140002ef9 <__mingw_GetSectionForAddress+0x2e>
   140002ef2:	b8 00 00 00 00       	mov    eax,0x0
   140002ef7:	eb 1c                	jmp    140002f15 <__mingw_GetSectionForAddress+0x4a>
   140002ef9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140002efd:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140002f01:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f05:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140002f09:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f0d:	48 89 c1             	mov    rcx,rax
   140002f10:	e8 57 fe ff ff       	call   140002d6c <_FindPESection>
   140002f15:	48 83 c4 30          	add    rsp,0x30
   140002f19:	5d                   	pop    rbp
   140002f1a:	c3                   	ret

0000000140002f1b <__mingw_GetSectionCount>:
   140002f1b:	55                   	push   rbp
   140002f1c:	48 89 e5             	mov    rbp,rsp
   140002f1f:	48 83 ec 30          	sub    rsp,0x30
   140002f23:	48 8b 05 76 86 00 00 	mov    rax,QWORD PTR [rip+0x8676]        # 14000b5a0 <.refptr.__ImageBase>
   140002f2a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002f2e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f32:	48 89 c1             	mov    rcx,rax
   140002f35:	e8 b6 fd ff ff       	call   140002cf0 <_ValidateImageBase>
   140002f3a:	85 c0                	test   eax,eax
   140002f3c:	75 07                	jne    140002f45 <__mingw_GetSectionCount+0x2a>
   140002f3e:	b8 00 00 00 00       	mov    eax,0x0
   140002f43:	eb 20                	jmp    140002f65 <__mingw_GetSectionCount+0x4a>
   140002f45:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f49:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002f4c:	48 63 d0             	movsxd rdx,eax
   140002f4f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002f53:	48 01 d0             	add    rax,rdx
   140002f56:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140002f5a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140002f5e:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140002f62:	0f b7 c0             	movzx  eax,ax
   140002f65:	48 83 c4 30          	add    rsp,0x30
   140002f69:	5d                   	pop    rbp
   140002f6a:	c3                   	ret

0000000140002f6b <_FindPESectionExec>:
   140002f6b:	55                   	push   rbp
   140002f6c:	48 89 e5             	mov    rbp,rsp
   140002f6f:	48 83 ec 40          	sub    rsp,0x40
   140002f73:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140002f77:	48 8b 05 22 86 00 00 	mov    rax,QWORD PTR [rip+0x8622]        # 14000b5a0 <.refptr.__ImageBase>
   140002f7e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140002f82:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f86:	48 89 c1             	mov    rcx,rax
   140002f89:	e8 62 fd ff ff       	call   140002cf0 <_ValidateImageBase>
   140002f8e:	85 c0                	test   eax,eax
   140002f90:	75 07                	jne    140002f99 <_FindPESectionExec+0x2e>
   140002f92:	b8 00 00 00 00       	mov    eax,0x0
   140002f97:	eb 78                	jmp    140003011 <_FindPESectionExec+0xa6>
   140002f99:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002f9d:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   140002fa0:	48 63 d0             	movsxd rdx,eax
   140002fa3:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140002fa7:	48 01 d0             	add    rax,rdx
   140002faa:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140002fae:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140002fb5:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fb9:	0f b7 40 14          	movzx  eax,WORD PTR [rax+0x14]
   140002fbd:	0f b7 d0             	movzx  edx,ax
   140002fc0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140002fc4:	48 01 d0             	add    rax,rdx
   140002fc7:	48 83 c0 18          	add    rax,0x18
   140002fcb:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140002fcf:	eb 2b                	jmp    140002ffc <_FindPESectionExec+0x91>
   140002fd1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fd5:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   140002fd8:	25 00 00 00 20       	and    eax,0x20000000
   140002fdd:	85 c0                	test   eax,eax
   140002fdf:	74 12                	je     140002ff3 <_FindPESectionExec+0x88>
   140002fe1:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140002fe6:	75 06                	jne    140002fee <_FindPESectionExec+0x83>
   140002fe8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140002fec:	eb 23                	jmp    140003011 <_FindPESectionExec+0xa6>
   140002fee:	48 83 6d 10 01       	sub    QWORD PTR [rbp+0x10],0x1
   140002ff3:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   140002ff7:	48 83 45 f8 28       	add    QWORD PTR [rbp-0x8],0x28
   140002ffc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003000:	0f b7 40 06          	movzx  eax,WORD PTR [rax+0x6]
   140003004:	0f b7 c0             	movzx  eax,ax
   140003007:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   14000300a:	72 c5                	jb     140002fd1 <_FindPESectionExec+0x66>
   14000300c:	b8 00 00 00 00       	mov    eax,0x0
   140003011:	48 83 c4 40          	add    rsp,0x40
   140003015:	5d                   	pop    rbp
   140003016:	c3                   	ret

0000000140003017 <_GetPEImageBase>:
   140003017:	55                   	push   rbp
   140003018:	48 89 e5             	mov    rbp,rsp
   14000301b:	48 83 ec 30          	sub    rsp,0x30
   14000301f:	48 8b 05 7a 85 00 00 	mov    rax,QWORD PTR [rip+0x857a]        # 14000b5a0 <.refptr.__ImageBase>
   140003026:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000302a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000302e:	48 89 c1             	mov    rcx,rax
   140003031:	e8 ba fc ff ff       	call   140002cf0 <_ValidateImageBase>
   140003036:	85 c0                	test   eax,eax
   140003038:	75 07                	jne    140003041 <_GetPEImageBase+0x2a>
   14000303a:	b8 00 00 00 00       	mov    eax,0x0
   14000303f:	eb 04                	jmp    140003045 <_GetPEImageBase+0x2e>
   140003041:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003045:	48 83 c4 30          	add    rsp,0x30
   140003049:	5d                   	pop    rbp
   14000304a:	c3                   	ret

000000014000304b <_IsNonwritableInCurrentImage>:
   14000304b:	55                   	push   rbp
   14000304c:	48 89 e5             	mov    rbp,rsp
   14000304f:	48 83 ec 40          	sub    rsp,0x40
   140003053:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003057:	48 8b 05 42 85 00 00 	mov    rax,QWORD PTR [rip+0x8542]        # 14000b5a0 <.refptr.__ImageBase>
   14000305e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003062:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003066:	48 89 c1             	mov    rcx,rax
   140003069:	e8 82 fc ff ff       	call   140002cf0 <_ValidateImageBase>
   14000306e:	85 c0                	test   eax,eax
   140003070:	75 07                	jne    140003079 <_IsNonwritableInCurrentImage+0x2e>
   140003072:	b8 00 00 00 00       	mov    eax,0x0
   140003077:	eb 3d                	jmp    1400030b6 <_IsNonwritableInCurrentImage+0x6b>
   140003079:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000307d:	48 2b 45 f8          	sub    rax,QWORD PTR [rbp-0x8]
   140003081:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003085:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003089:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000308d:	48 89 c1             	mov    rcx,rax
   140003090:	e8 d7 fc ff ff       	call   140002d6c <_FindPESection>
   140003095:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003099:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   14000309e:	75 07                	jne    1400030a7 <_IsNonwritableInCurrentImage+0x5c>
   1400030a0:	b8 00 00 00 00       	mov    eax,0x0
   1400030a5:	eb 0f                	jmp    1400030b6 <_IsNonwritableInCurrentImage+0x6b>
   1400030a7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400030ab:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400030ae:	f7 d0                	not    eax
   1400030b0:	c1 e8 1f             	shr    eax,0x1f
   1400030b3:	0f b6 c0             	movzx  eax,al
   1400030b6:	48 83 c4 40          	add    rsp,0x40
   1400030ba:	5d                   	pop    rbp
   1400030bb:	c3                   	ret

00000001400030bc <__mingw_enum_import_library_names>:
   1400030bc:	55                   	push   rbp
   1400030bd:	48 89 e5             	mov    rbp,rsp
   1400030c0:	48 83 ec 50          	sub    rsp,0x50
   1400030c4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400030c7:	48 8b 05 d2 84 00 00 	mov    rax,QWORD PTR [rip+0x84d2]        # 14000b5a0 <.refptr.__ImageBase>
   1400030ce:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400030d2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030d6:	48 89 c1             	mov    rcx,rax
   1400030d9:	e8 12 fc ff ff       	call   140002cf0 <_ValidateImageBase>
   1400030de:	85 c0                	test   eax,eax
   1400030e0:	75 0a                	jne    1400030ec <__mingw_enum_import_library_names+0x30>
   1400030e2:	b8 00 00 00 00       	mov    eax,0x0
   1400030e7:	e9 ab 00 00 00       	jmp    140003197 <__mingw_enum_import_library_names+0xdb>
   1400030ec:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030f0:	8b 40 3c             	mov    eax,DWORD PTR [rax+0x3c]
   1400030f3:	48 63 d0             	movsxd rdx,eax
   1400030f6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400030fa:	48 01 d0             	add    rax,rdx
   1400030fd:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140003101:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140003105:	8b 80 90 00 00 00    	mov    eax,DWORD PTR [rax+0x90]
   14000310b:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   14000310e:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140003112:	75 07                	jne    14000311b <__mingw_enum_import_library_names+0x5f>
   140003114:	b8 00 00 00 00       	mov    eax,0x0
   140003119:	eb 7c                	jmp    140003197 <__mingw_enum_import_library_names+0xdb>
   14000311b:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000311e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003122:	48 89 c1             	mov    rcx,rax
   140003125:	e8 42 fc ff ff       	call   140002d6c <_FindPESection>
   14000312a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000312e:	48 83 7d d8 00       	cmp    QWORD PTR [rbp-0x28],0x0
   140003133:	75 07                	jne    14000313c <__mingw_enum_import_library_names+0x80>
   140003135:	b8 00 00 00 00       	mov    eax,0x0
   14000313a:	eb 5b                	jmp    140003197 <__mingw_enum_import_library_names+0xdb>
   14000313c:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000313f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003143:	48 01 d0             	add    rax,rdx
   140003146:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000314a:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   14000314f:	75 07                	jne    140003158 <__mingw_enum_import_library_names+0x9c>
   140003151:	b8 00 00 00 00       	mov    eax,0x0
   140003156:	eb 3f                	jmp    140003197 <__mingw_enum_import_library_names+0xdb>
   140003158:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000315c:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000315f:	85 c0                	test   eax,eax
   140003161:	75 0b                	jne    14000316e <__mingw_enum_import_library_names+0xb2>
   140003163:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003167:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000316a:	85 c0                	test   eax,eax
   14000316c:	74 23                	je     140003191 <__mingw_enum_import_library_names+0xd5>
   14000316e:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140003172:	7f 12                	jg     140003186 <__mingw_enum_import_library_names+0xca>
   140003174:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003178:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000317b:	89 c2                	mov    edx,eax
   14000317d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003181:	48 01 d0             	add    rax,rdx
   140003184:	eb 11                	jmp    140003197 <__mingw_enum_import_library_names+0xdb>
   140003186:	83 6d 10 01          	sub    DWORD PTR [rbp+0x10],0x1
   14000318a:	48 83 45 f8 14       	add    QWORD PTR [rbp-0x8],0x14
   14000318f:	eb c7                	jmp    140003158 <__mingw_enum_import_library_names+0x9c>
   140003191:	90                   	nop
   140003192:	b8 00 00 00 00       	mov    eax,0x0
   140003197:	48 83 c4 50          	add    rsp,0x50
   14000319b:	5d                   	pop    rbp
   14000319c:	c3                   	ret
   14000319d:	90                   	nop
   14000319e:	90                   	nop
   14000319f:	90                   	nop

00000001400031a0 <___chkstk_ms>:
   1400031a0:	51                   	push   rcx
   1400031a1:	50                   	push   rax
   1400031a2:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400031a8:	48 8d 4c 24 18       	lea    rcx,[rsp+0x18]
   1400031ad:	72 19                	jb     1400031c8 <___chkstk_ms+0x28>
   1400031af:	48 81 e9 00 10 00 00 	sub    rcx,0x1000
   1400031b6:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400031ba:	48 2d 00 10 00 00    	sub    rax,0x1000
   1400031c0:	48 3d 00 10 00 00    	cmp    rax,0x1000
   1400031c6:	77 e7                	ja     1400031af <___chkstk_ms+0xf>
   1400031c8:	48 29 c1             	sub    rcx,rax
   1400031cb:	48 83 09 00          	or     QWORD PTR [rcx],0x0
   1400031cf:	58                   	pop    rax
   1400031d0:	59                   	pop    rcx
   1400031d1:	c3                   	ret
   1400031d2:	90                   	nop
   1400031d3:	90                   	nop
   1400031d4:	90                   	nop
   1400031d5:	90                   	nop
   1400031d6:	90                   	nop
   1400031d7:	90                   	nop
   1400031d8:	90                   	nop
   1400031d9:	90                   	nop
   1400031da:	90                   	nop
   1400031db:	90                   	nop
   1400031dc:	90                   	nop
   1400031dd:	90                   	nop
   1400031de:	90                   	nop
   1400031df:	90                   	nop

00000001400031e0 <__mingw_printf>:
   1400031e0:	55                   	push   rbp
   1400031e1:	53                   	push   rbx
   1400031e2:	48 83 ec 48          	sub    rsp,0x48
   1400031e6:	48 8d 6c 24 40       	lea    rbp,[rsp+0x40]
   1400031eb:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   1400031ef:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400031f3:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   1400031f7:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   1400031fb:	48 8d 45 28          	lea    rax,[rbp+0x28]
   1400031ff:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003203:	b9 01 00 00 00       	mov    ecx,0x1
   140003208:	e8 c3 5e 00 00       	call   1400090d0 <__acrt_iob_func>
   14000320d:	48 89 c1             	mov    rcx,rax
   140003210:	e8 3b 5d 00 00       	call   140008f50 <_lock_file>
   140003215:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
   140003219:	b9 01 00 00 00       	mov    ecx,0x1
   14000321e:	e8 ad 5e 00 00       	call   1400090d0 <__acrt_iob_func>
   140003223:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003227:	48 89 5c 24 20       	mov    QWORD PTR [rsp+0x20],rbx
   14000322c:	49 89 d1             	mov    r9,rdx
   14000322f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140003235:	48 89 c2             	mov    rdx,rax
   140003238:	b9 00 60 00 00       	mov    ecx,0x6000
   14000323d:	e8 b1 1f 00 00       	call   1400051f3 <__mingw_pformat>
   140003242:	89 c3                	mov    ebx,eax
   140003244:	b9 01 00 00 00       	mov    ecx,0x1
   140003249:	e8 82 5e 00 00       	call   1400090d0 <__acrt_iob_func>
   14000324e:	48 89 c1             	mov    rcx,rax
   140003251:	e8 84 5d 00 00       	call   140008fda <_unlock_file>
   140003256:	89 d8                	mov    eax,ebx
   140003258:	48 83 c4 48          	add    rsp,0x48
   14000325c:	5b                   	pop    rbx
   14000325d:	5d                   	pop    rbp
   14000325e:	c3                   	ret
   14000325f:	90                   	nop

0000000140003260 <__pformat_putc>:
   140003260:	55                   	push   rbp
   140003261:	48 89 e5             	mov    rbp,rsp
   140003264:	48 83 ec 20          	sub    rsp,0x20
   140003268:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000326b:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000326f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003273:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003276:	25 00 40 00 00       	and    eax,0x4000
   14000327b:	85 c0                	test   eax,eax
   14000327d:	75 12                	jne    140003291 <__pformat_putc+0x31>
   14000327f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003283:	8b 50 28             	mov    edx,DWORD PTR [rax+0x28]
   140003286:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000328a:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   14000328d:	39 c2                	cmp    edx,eax
   14000328f:	7e 3b                	jle    1400032cc <__pformat_putc+0x6c>
   140003291:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003295:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003298:	25 00 20 00 00       	and    eax,0x2000
   14000329d:	85 c0                	test   eax,eax
   14000329f:	74 13                	je     1400032b4 <__pformat_putc+0x54>
   1400032a1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032a5:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400032a8:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400032ab:	89 c1                	mov    ecx,eax
   1400032ad:	e8 56 64 00 00       	call   140009708 <fputc>
   1400032b2:	eb 18                	jmp    1400032cc <__pformat_putc+0x6c>
   1400032b4:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032b8:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   1400032bb:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032bf:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400032c2:	48 98                	cdqe
   1400032c4:	48 01 d0             	add    rax,rdx
   1400032c7:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400032ca:	88 10                	mov    BYTE PTR [rax],dl
   1400032cc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032d0:	8b 40 24             	mov    eax,DWORD PTR [rax+0x24]
   1400032d3:	8d 50 01             	lea    edx,[rax+0x1]
   1400032d6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400032da:	89 50 24             	mov    DWORD PTR [rax+0x24],edx
   1400032dd:	90                   	nop
   1400032de:	48 83 c4 20          	add    rsp,0x20
   1400032e2:	5d                   	pop    rbp
   1400032e3:	c3                   	ret

00000001400032e4 <__pformat_putchars>:
   1400032e4:	55                   	push   rbp
   1400032e5:	48 89 e5             	mov    rbp,rsp
   1400032e8:	48 83 ec 20          	sub    rsp,0x20
   1400032ec:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400032f0:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400032f3:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400032f7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400032fb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400032fe:	85 c0                	test   eax,eax
   140003300:	78 16                	js     140003318 <__pformat_putchars+0x34>
   140003302:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003306:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003309:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   14000330c:	7e 0a                	jle    140003318 <__pformat_putchars+0x34>
   14000330e:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003312:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003315:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   140003318:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000331c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000331f:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003322:	7d 15                	jge    140003339 <__pformat_putchars+0x55>
   140003324:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003328:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000332b:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000332e:	89 c2                	mov    edx,eax
   140003330:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003334:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003337:	eb 0b                	jmp    140003344 <__pformat_putchars+0x60>
   140003339:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000333d:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003344:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003348:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000334b:	85 c0                	test   eax,eax
   14000334d:	7e 57                	jle    1400033a6 <__pformat_putchars+0xc2>
   14000334f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003353:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003356:	25 00 04 00 00       	and    eax,0x400
   14000335b:	85 c0                	test   eax,eax
   14000335d:	75 47                	jne    1400033a6 <__pformat_putchars+0xc2>
   14000335f:	eb 11                	jmp    140003372 <__pformat_putchars+0x8e>
   140003361:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003365:	48 89 c2             	mov    rdx,rax
   140003368:	b9 20 00 00 00       	mov    ecx,0x20
   14000336d:	e8 ee fe ff ff       	call   140003260 <__pformat_putc>
   140003372:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003376:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003379:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000337c:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003380:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003383:	85 c0                	test   eax,eax
   140003385:	75 da                	jne    140003361 <__pformat_putchars+0x7d>
   140003387:	eb 1d                	jmp    1400033a6 <__pformat_putchars+0xc2>
   140003389:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000338d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003391:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003395:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003398:	0f be c0             	movsx  eax,al
   14000339b:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000339f:	89 c1                	mov    ecx,eax
   1400033a1:	e8 ba fe ff ff       	call   140003260 <__pformat_putc>
   1400033a6:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400033a9:	8d 50 ff             	lea    edx,[rax-0x1]
   1400033ac:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400033af:	85 c0                	test   eax,eax
   1400033b1:	75 d6                	jne    140003389 <__pformat_putchars+0xa5>
   1400033b3:	eb 11                	jmp    1400033c6 <__pformat_putchars+0xe2>
   1400033b5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033b9:	48 89 c2             	mov    rdx,rax
   1400033bc:	b9 20 00 00 00       	mov    ecx,0x20
   1400033c1:	e8 9a fe ff ff       	call   140003260 <__pformat_putc>
   1400033c6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400033ca:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400033cd:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400033d0:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400033d4:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400033d7:	85 c0                	test   eax,eax
   1400033d9:	7f da                	jg     1400033b5 <__pformat_putchars+0xd1>
   1400033db:	90                   	nop
   1400033dc:	90                   	nop
   1400033dd:	48 83 c4 20          	add    rsp,0x20
   1400033e1:	5d                   	pop    rbp
   1400033e2:	c3                   	ret

00000001400033e3 <__pformat_puts>:
   1400033e3:	55                   	push   rbp
   1400033e4:	48 89 e5             	mov    rbp,rsp
   1400033e7:	48 83 ec 20          	sub    rsp,0x20
   1400033eb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400033ef:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400033f3:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400033f8:	75 0b                	jne    140003405 <__pformat_puts+0x22>
   1400033fa:	48 8d 05 4f 7f 00 00 	lea    rax,[rip+0x7f4f]        # 14000b350 <.rdata>
   140003401:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140003405:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003409:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000340c:	85 c0                	test   eax,eax
   14000340e:	78 2f                	js     14000343f <__pformat_puts+0x5c>
   140003410:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140003414:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003417:	48 63 d0             	movsxd rdx,eax
   14000341a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000341e:	48 89 c1             	mov    rcx,rax
   140003421:	e8 4a 5a 00 00       	call   140008e70 <strnlen>
   140003426:	89 c1                	mov    ecx,eax
   140003428:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   14000342c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003430:	49 89 d0             	mov    r8,rdx
   140003433:	89 ca                	mov    edx,ecx
   140003435:	48 89 c1             	mov    rcx,rax
   140003438:	e8 a7 fe ff ff       	call   1400032e4 <__pformat_putchars>
   14000343d:	eb 23                	jmp    140003462 <__pformat_puts+0x7f>
   14000343f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003443:	48 89 c1             	mov    rcx,rax
   140003446:	e8 0d 63 00 00       	call   140009758 <strlen>
   14000344b:	89 c1                	mov    ecx,eax
   14000344d:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003451:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003455:	49 89 d0             	mov    r8,rdx
   140003458:	89 ca                	mov    edx,ecx
   14000345a:	48 89 c1             	mov    rcx,rax
   14000345d:	e8 82 fe ff ff       	call   1400032e4 <__pformat_putchars>
   140003462:	90                   	nop
   140003463:	48 83 c4 20          	add    rsp,0x20
   140003467:	5d                   	pop    rbp
   140003468:	c3                   	ret

0000000140003469 <__pformat_wputchars>:
   140003469:	55                   	push   rbp
   14000346a:	48 89 e5             	mov    rbp,rsp
   14000346d:	48 83 ec 50          	sub    rsp,0x50
   140003471:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140003475:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003478:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   14000347c:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   140003483:	00 
   140003484:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003488:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000348b:	85 c0                	test   eax,eax
   14000348d:	78 16                	js     1400034a5 <__pformat_wputchars+0x3c>
   14000348f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003493:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003496:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   140003499:	7e 0a                	jle    1400034a5 <__pformat_wputchars+0x3c>
   14000349b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000349f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400034a2:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   1400034a5:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034a9:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034ac:	39 45 18             	cmp    DWORD PTR [rbp+0x18],eax
   1400034af:	7d 15                	jge    1400034c6 <__pformat_wputchars+0x5d>
   1400034b1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034b5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034b8:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400034bb:	89 c2                	mov    edx,eax
   1400034bd:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034c1:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400034c4:	eb 0b                	jmp    1400034d1 <__pformat_wputchars+0x68>
   1400034c6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034ca:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400034d1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034d5:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400034d8:	85 c0                	test   eax,eax
   1400034da:	7e 6e                	jle    14000354a <__pformat_wputchars+0xe1>
   1400034dc:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034e0:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400034e3:	25 00 04 00 00       	and    eax,0x400
   1400034e8:	85 c0                	test   eax,eax
   1400034ea:	75 5e                	jne    14000354a <__pformat_wputchars+0xe1>
   1400034ec:	eb 11                	jmp    1400034ff <__pformat_wputchars+0x96>
   1400034ee:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400034f2:	48 89 c2             	mov    rdx,rax
   1400034f5:	b9 20 00 00 00       	mov    ecx,0x20
   1400034fa:	e8 61 fd ff ff       	call   140003260 <__pformat_putc>
   1400034ff:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003503:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003506:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003509:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   14000350d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003510:	85 c0                	test   eax,eax
   140003512:	75 da                	jne    1400034ee <__pformat_wputchars+0x85>
   140003514:	eb 34                	jmp    14000354a <__pformat_wputchars+0xe1>
   140003516:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   14000351a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000351e:	eb 1d                	jmp    14000353d <__pformat_wputchars+0xd4>
   140003520:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003524:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003528:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000352c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000352f:	0f be c0             	movsx  eax,al
   140003532:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140003536:	89 c1                	mov    ecx,eax
   140003538:	e8 23 fd ff ff       	call   140003260 <__pformat_putc>
   14000353d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003540:	8d 50 ff             	lea    edx,[rax-0x1]
   140003543:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003546:	85 c0                	test   eax,eax
   140003548:	7f d6                	jg     140003520 <__pformat_wputchars+0xb7>
   14000354a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000354d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003550:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003553:	85 c0                	test   eax,eax
   140003555:	7e 41                	jle    140003598 <__pformat_wputchars+0x12f>
   140003557:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000355b:	48 8d 50 02          	lea    rdx,[rax+0x2]
   14000355f:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140003563:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140003566:	48 8d 4d d8          	lea    rcx,[rbp-0x28]
   14000356a:	0f b7 d0             	movzx  edx,ax
   14000356d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003571:	49 89 c8             	mov    r8,rcx
   140003574:	48 89 c1             	mov    rcx,rax
   140003577:	e8 84 5b 00 00       	call   140009100 <wcrtomb>
   14000357c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000357f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003583:	7f 91                	jg     140003516 <__pformat_wputchars+0xad>
   140003585:	eb 11                	jmp    140003598 <__pformat_wputchars+0x12f>
   140003587:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000358b:	48 89 c2             	mov    rdx,rax
   14000358e:	b9 20 00 00 00       	mov    ecx,0x20
   140003593:	e8 c8 fc ff ff       	call   140003260 <__pformat_putc>
   140003598:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000359c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000359f:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400035a2:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400035a6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400035a9:	85 c0                	test   eax,eax
   1400035ab:	7f da                	jg     140003587 <__pformat_wputchars+0x11e>
   1400035ad:	90                   	nop
   1400035ae:	90                   	nop
   1400035af:	48 83 c4 50          	add    rsp,0x50
   1400035b3:	5d                   	pop    rbp
   1400035b4:	c3                   	ret

00000001400035b5 <__pformat_wcputs>:
   1400035b5:	55                   	push   rbp
   1400035b6:	48 89 e5             	mov    rbp,rsp
   1400035b9:	48 83 ec 20          	sub    rsp,0x20
   1400035bd:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400035c1:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400035c5:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400035ca:	75 0b                	jne    1400035d7 <__pformat_wcputs+0x22>
   1400035cc:	48 8d 05 85 7d 00 00 	lea    rax,[rip+0x7d85]        # 14000b358 <.rdata+0x8>
   1400035d3:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400035d7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035db:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035de:	85 c0                	test   eax,eax
   1400035e0:	78 2f                	js     140003611 <__pformat_wcputs+0x5c>
   1400035e2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400035e6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400035e9:	48 63 d0             	movsxd rdx,eax
   1400035ec:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400035f0:	48 89 c1             	mov    rcx,rax
   1400035f3:	e8 28 58 00 00       	call   140008e20 <wcsnlen>
   1400035f8:	89 c1                	mov    ecx,eax
   1400035fa:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400035fe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003602:	49 89 d0             	mov    r8,rdx
   140003605:	89 ca                	mov    edx,ecx
   140003607:	48 89 c1             	mov    rcx,rax
   14000360a:	e8 5a fe ff ff       	call   140003469 <__pformat_wputchars>
   14000360f:	eb 23                	jmp    140003634 <__pformat_wcputs+0x7f>
   140003611:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003615:	48 89 c1             	mov    rcx,rax
   140003618:	e8 53 61 00 00       	call   140009770 <wcslen>
   14000361d:	89 c1                	mov    ecx,eax
   14000361f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140003623:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140003627:	49 89 d0             	mov    r8,rdx
   14000362a:	89 ca                	mov    edx,ecx
   14000362c:	48 89 c1             	mov    rcx,rax
   14000362f:	e8 35 fe ff ff       	call   140003469 <__pformat_wputchars>
   140003634:	90                   	nop
   140003635:	48 83 c4 20          	add    rsp,0x20
   140003639:	5d                   	pop    rbp
   14000363a:	c3                   	ret

000000014000363b <__pformat_int_bufsiz>:
   14000363b:	55                   	push   rbp
   14000363c:	48 89 e5             	mov    rbp,rsp
   14000363f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140003642:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140003645:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140003649:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000364c:	83 e8 01             	sub    eax,0x1
   14000364f:	48 98                	cdqe
   140003651:	48 83 c0 40          	add    rax,0x40
   140003655:	8b 55 18             	mov    edx,DWORD PTR [rbp+0x18]
   140003658:	48 63 ca             	movsxd rcx,edx
   14000365b:	ba 00 00 00 00       	mov    edx,0x0
   140003660:	48 f7 f1             	div    rcx
   140003663:	89 c2                	mov    edx,eax
   140003665:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140003668:	01 d0                	add    eax,edx
   14000366a:	89 45 18             	mov    DWORD PTR [rbp+0x18],eax
   14000366d:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003671:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003674:	ba 00 00 00 00       	mov    edx,0x0
   140003679:	85 c0                	test   eax,eax
   14000367b:	0f 48 c2             	cmovs  eax,edx
   14000367e:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   140003681:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003685:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003688:	25 00 10 00 00       	and    eax,0x1000
   14000368d:	85 c0                	test   eax,eax
   14000368f:	74 29                	je     1400036ba <__pformat_int_bufsiz+0x7f>
   140003691:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003695:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140003699:	66 85 c0             	test   ax,ax
   14000369c:	74 1c                	je     1400036ba <__pformat_int_bufsiz+0x7f>
   14000369e:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400036a1:	48 63 d0             	movsxd rdx,eax
   1400036a4:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   1400036ab:	48 89 d1             	mov    rcx,rdx
   1400036ae:	48 c1 e9 20          	shr    rcx,0x20
   1400036b2:	99                   	cdq
   1400036b3:	89 c8                	mov    eax,ecx
   1400036b5:	29 d0                	sub    eax,edx
   1400036b7:	01 45 18             	add    DWORD PTR [rbp+0x18],eax
   1400036ba:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400036be:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400036c1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400036c4:	39 c2                	cmp    edx,eax
   1400036c6:	0f 4d c2             	cmovge eax,edx
   1400036c9:	5d                   	pop    rbp
   1400036ca:	c3                   	ret

00000001400036cb <__pformat_int>:
   1400036cb:	55                   	push   rbp
   1400036cc:	53                   	push   rbx
   1400036cd:	48 83 ec 58          	sub    rsp,0x58
   1400036d1:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400036d6:	48 89 cb             	mov    rbx,rcx
   1400036d9:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
   1400036dc:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
   1400036e0:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
   1400036e4:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
   1400036e8:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400036ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400036f0:	49 89 c0             	mov    r8,rax
   1400036f3:	ba 03 00 00 00       	mov    edx,0x3
   1400036f8:	b9 01 00 00 00       	mov    ecx,0x1
   1400036fd:	e8 39 ff ff ff       	call   14000363b <__pformat_int_bufsiz>
   140003702:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140003705:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
   14000370c:	00 
   14000370d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140003710:	48 98                	cdqe
   140003712:	48 83 c0 0f          	add    rax,0xf
   140003716:	48 c1 e8 04          	shr    rax,0x4
   14000371a:	48 c1 e0 04          	shl    rax,0x4
   14000371e:	e8 7d fa ff ff       	call   1400031a0 <___chkstk_ms>
   140003723:	48 29 c4             	sub    rsp,rax
   140003726:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000372b:	48 83 c0 0f          	add    rax,0xf
   14000372f:	48 c1 e8 04          	shr    rax,0x4
   140003733:	48 c1 e0 04          	shl    rax,0x4
   140003737:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000373b:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000373f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140003743:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003747:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000374a:	25 80 00 00 00       	and    eax,0x80
   14000374f:	85 c0                	test   eax,eax
   140003751:	0f 84 ea 00 00 00    	je     140003841 <__pformat_int+0x176>
   140003757:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000375b:	48 85 c0             	test   rax,rax
   14000375e:	79 10                	jns    140003770 <__pformat_int+0xa5>
   140003760:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003764:	48 f7 d8             	neg    rax
   140003767:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000376b:	e9 d1 00 00 00       	jmp    140003841 <__pformat_int+0x176>
   140003770:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003774:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003777:	24 7f                	and    al,0x7f
   140003779:	89 c2                	mov    edx,eax
   14000377b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000377f:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003782:	e9 ba 00 00 00       	jmp    140003841 <__pformat_int+0x176>
   140003787:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000378b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000378f:	74 54                	je     1400037e5 <__pformat_int+0x11a>
   140003791:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003795:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003798:	25 00 10 00 00       	and    eax,0x1000
   14000379d:	85 c0                	test   eax,eax
   14000379f:	74 44                	je     1400037e5 <__pformat_int+0x11a>
   1400037a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400037a5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400037a9:	66 85 c0             	test   ax,ax
   1400037ac:	74 37                	je     1400037e5 <__pformat_int+0x11a>
   1400037ae:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037b2:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400037b6:	48 89 c2             	mov    rdx,rax
   1400037b9:	48 89 d0             	mov    rax,rdx
   1400037bc:	48 c1 f8 3f          	sar    rax,0x3f
   1400037c0:	48 c1 e8 3e          	shr    rax,0x3e
   1400037c4:	48 01 c2             	add    rdx,rax
   1400037c7:	83 e2 03             	and    edx,0x3
   1400037ca:	48 29 c2             	sub    rdx,rax
   1400037cd:	48 89 d0             	mov    rax,rdx
   1400037d0:	48 83 f8 03          	cmp    rax,0x3
   1400037d4:	75 0f                	jne    1400037e5 <__pformat_int+0x11a>
   1400037d6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400037da:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400037de:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400037e2:	c6 00 2c             	mov    BYTE PTR [rax],0x2c
   1400037e5:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
   1400037e9:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   1400037f0:	cc cc cc 
   1400037f3:	48 89 c8             	mov    rax,rcx
   1400037f6:	48 f7 e2             	mul    rdx
   1400037f9:	48 c1 ea 03          	shr    rdx,0x3
   1400037fd:	48 89 d0             	mov    rax,rdx
   140003800:	48 c1 e0 02          	shl    rax,0x2
   140003804:	48 01 d0             	add    rax,rdx
   140003807:	48 01 c0             	add    rax,rax
   14000380a:	48 29 c1             	sub    rcx,rax
   14000380d:	48 89 ca             	mov    rdx,rcx
   140003810:	89 d0                	mov    eax,edx
   140003812:	8d 48 30             	lea    ecx,[rax+0x30]
   140003815:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003819:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000381d:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003821:	89 ca                	mov    edx,ecx
   140003823:	88 10                	mov    BYTE PTR [rax],dl
   140003825:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003829:	48 ba cd cc cc cc cc 	movabs rdx,0xcccccccccccccccd
   140003830:	cc cc cc 
   140003833:	48 f7 e2             	mul    rdx
   140003836:	48 89 d0             	mov    rax,rdx
   140003839:	48 c1 e8 03          	shr    rax,0x3
   14000383d:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140003841:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140003845:	48 85 c0             	test   rax,rax
   140003848:	0f 85 39 ff ff ff    	jne    140003787 <__pformat_int+0xbc>
   14000384e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003852:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003855:	85 c0                	test   eax,eax
   140003857:	7e 3e                	jle    140003897 <__pformat_int+0x1cc>
   140003859:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000385d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003860:	89 c1                	mov    ecx,eax
   140003862:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003866:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   14000386a:	89 c2                	mov    edx,eax
   14000386c:	89 c8                	mov    eax,ecx
   14000386e:	29 d0                	sub    eax,edx
   140003870:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140003873:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140003877:	7e 1e                	jle    140003897 <__pformat_int+0x1cc>
   140003879:	eb 0f                	jmp    14000388a <__pformat_int+0x1bf>
   14000387b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000387f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003883:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003887:	c6 00 30             	mov    BYTE PTR [rax],0x30
   14000388a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   14000388d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003890:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx
   140003893:	85 c0                	test   eax,eax
   140003895:	7f e4                	jg     14000387b <__pformat_int+0x1b0>
   140003897:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000389b:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   14000389f:	75 1a                	jne    1400038bb <__pformat_int+0x1f0>
   1400038a1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038a5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400038a8:	85 c0                	test   eax,eax
   1400038aa:	74 0f                	je     1400038bb <__pformat_int+0x1f0>
   1400038ac:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038b0:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400038b4:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400038b8:	c6 00 30             	mov    BYTE PTR [rax],0x30
   1400038bb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038bf:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038c2:	85 c0                	test   eax,eax
   1400038c4:	0f 8e ce 00 00 00    	jle    140003998 <__pformat_int+0x2cd>
   1400038ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ce:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038d1:	89 c1                	mov    ecx,eax
   1400038d3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400038d7:	48 2b 45 e8          	sub    rax,QWORD PTR [rbp-0x18]
   1400038db:	89 c2                	mov    edx,eax
   1400038dd:	89 c8                	mov    eax,ecx
   1400038df:	29 d0                	sub    eax,edx
   1400038e1:	89 c2                	mov    edx,eax
   1400038e3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038e7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400038ea:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038ee:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400038f1:	85 c0                	test   eax,eax
   1400038f3:	0f 8e 9f 00 00 00    	jle    140003998 <__pformat_int+0x2cd>
   1400038f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400038fd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003900:	25 c0 01 00 00       	and    eax,0x1c0
   140003905:	85 c0                	test   eax,eax
   140003907:	74 11                	je     14000391a <__pformat_int+0x24f>
   140003909:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000390d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003910:	8d 50 ff             	lea    edx,[rax-0x1]
   140003913:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003917:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000391a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000391e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003921:	85 c0                	test   eax,eax
   140003923:	79 3b                	jns    140003960 <__pformat_int+0x295>
   140003925:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003929:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000392c:	25 00 06 00 00       	and    eax,0x600
   140003931:	3d 00 02 00 00       	cmp    eax,0x200
   140003936:	75 28                	jne    140003960 <__pformat_int+0x295>
   140003938:	eb 0f                	jmp    140003949 <__pformat_int+0x27e>
   14000393a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000393e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003942:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140003946:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003949:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000394d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003950:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003953:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003957:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000395a:	85 c0                	test   eax,eax
   14000395c:	7f dc                	jg     14000393a <__pformat_int+0x26f>
   14000395e:	eb 38                	jmp    140003998 <__pformat_int+0x2cd>
   140003960:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003964:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003967:	25 00 04 00 00       	and    eax,0x400
   14000396c:	85 c0                	test   eax,eax
   14000396e:	75 28                	jne    140003998 <__pformat_int+0x2cd>
   140003970:	eb 11                	jmp    140003983 <__pformat_int+0x2b8>
   140003972:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003976:	48 89 c2             	mov    rdx,rax
   140003979:	b9 20 00 00 00       	mov    ecx,0x20
   14000397e:	e8 dd f8 ff ff       	call   140003260 <__pformat_putc>
   140003983:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003987:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000398a:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000398d:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003991:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003994:	85 c0                	test   eax,eax
   140003996:	7f da                	jg     140003972 <__pformat_int+0x2a7>
   140003998:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000399c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000399f:	25 80 00 00 00       	and    eax,0x80
   1400039a4:	85 c0                	test   eax,eax
   1400039a6:	74 11                	je     1400039b9 <__pformat_int+0x2ee>
   1400039a8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039ac:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039b0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039b4:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   1400039b7:	eb 5a                	jmp    140003a13 <__pformat_int+0x348>
   1400039b9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039bd:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039c0:	25 00 01 00 00       	and    eax,0x100
   1400039c5:	85 c0                	test   eax,eax
   1400039c7:	74 11                	je     1400039da <__pformat_int+0x30f>
   1400039c9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039cd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039d1:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039d5:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400039d8:	eb 39                	jmp    140003a13 <__pformat_int+0x348>
   1400039da:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400039de:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400039e1:	83 e0 40             	and    eax,0x40
   1400039e4:	85 c0                	test   eax,eax
   1400039e6:	74 2b                	je     140003a13 <__pformat_int+0x348>
   1400039e8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400039ec:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400039f0:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400039f4:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400039f7:	eb 1a                	jmp    140003a13 <__pformat_int+0x348>
   1400039f9:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   1400039fe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003a02:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003a05:	0f be c0             	movsx  eax,al
   140003a08:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003a0c:	89 c1                	mov    ecx,eax
   140003a0e:	e8 4d f8 ff ff       	call   140003260 <__pformat_putc>
   140003a13:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140003a17:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140003a1b:	72 dc                	jb     1400039f9 <__pformat_int+0x32e>
   140003a1d:	eb 11                	jmp    140003a30 <__pformat_int+0x365>
   140003a1f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003a23:	48 89 c2             	mov    rdx,rax
   140003a26:	b9 20 00 00 00       	mov    ecx,0x20
   140003a2b:	e8 30 f8 ff ff       	call   140003260 <__pformat_putc>
   140003a30:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140003a34:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003a37:	8d 48 ff             	lea    ecx,[rax-0x1]
   140003a3a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140003a3e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140003a41:	85 c0                	test   eax,eax
   140003a43:	7f da                	jg     140003a1f <__pformat_int+0x354>
   140003a45:	90                   	nop
   140003a46:	90                   	nop
   140003a47:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003a4b:	5b                   	pop    rbx
   140003a4c:	5d                   	pop    rbp
   140003a4d:	c3                   	ret

0000000140003a4e <__pformat_xint>:
   140003a4e:	55                   	push   rbp
   140003a4f:	53                   	push   rbx
   140003a50:	48 83 ec 68          	sub    rsp,0x68
   140003a54:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003a59:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003a5c:	48 89 d3             	mov    rbx,rdx
   140003a5f:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140003a62:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
   140003a66:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003a6a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   140003a6e:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003a72:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003a76:	74 1e                	je     140003a96 <__pformat_xint+0x48>
   140003a78:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003a7c:	74 06                	je     140003a84 <__pformat_xint+0x36>
   140003a7e:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003a82:	75 09                	jne    140003a8d <__pformat_xint+0x3f>
   140003a84:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003a8b:	eb 10                	jmp    140003a9d <__pformat_xint+0x4f>
   140003a8d:	c7 45 f8 04 00 00 00 	mov    DWORD PTR [rbp-0x8],0x4
   140003a94:	eb 07                	jmp    140003a9d <__pformat_xint+0x4f>
   140003a96:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140003a9d:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003aa1:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003aa4:	49 89 d0             	mov    r8,rdx
   140003aa7:	89 c2                	mov    edx,eax
   140003aa9:	b9 02 00 00 00       	mov    ecx,0x2
   140003aae:	e8 88 fb ff ff       	call   14000363b <__pformat_int_bufsiz>
   140003ab3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140003ab6:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
   140003abd:	00 
   140003abe:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140003ac1:	48 98                	cdqe
   140003ac3:	48 83 c0 0f          	add    rax,0xf
   140003ac7:	48 c1 e8 04          	shr    rax,0x4
   140003acb:	48 c1 e0 04          	shl    rax,0x4
   140003acf:	e8 cc f6 ff ff       	call   1400031a0 <___chkstk_ms>
   140003ad4:	48 29 c4             	sub    rsp,rax
   140003ad7:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   140003adc:	48 83 c0 0f          	add    rax,0xf
   140003ae0:	48 c1 e8 04          	shr    rax,0x4
   140003ae4:	48 c1 e0 04          	shl    rax,0x4
   140003ae8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140003aec:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140003af0:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140003af4:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003af8:	74 1e                	je     140003b18 <__pformat_xint+0xca>
   140003afa:	83 7d 20 62          	cmp    DWORD PTR [rbp+0x20],0x62
   140003afe:	74 06                	je     140003b06 <__pformat_xint+0xb8>
   140003b00:	83 7d 20 42          	cmp    DWORD PTR [rbp+0x20],0x42
   140003b04:	75 09                	jne    140003b0f <__pformat_xint+0xc1>
   140003b06:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140003b0d:	eb 10                	jmp    140003b1f <__pformat_xint+0xd1>
   140003b0f:	c7 45 ec 0f 00 00 00 	mov    DWORD PTR [rbp-0x14],0xf
   140003b16:	eb 67                	jmp    140003b7f <__pformat_xint+0x131>
   140003b18:	c7 45 ec 07 00 00 00 	mov    DWORD PTR [rbp-0x14],0x7
   140003b1f:	eb 5e                	jmp    140003b7f <__pformat_xint+0x131>
   140003b21:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b25:	89 c2                	mov    edx,eax
   140003b27:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140003b2a:	21 d0                	and    eax,edx
   140003b2c:	8d 48 30             	lea    ecx,[rax+0x30]
   140003b2f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b33:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003b37:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003b3b:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140003b3f:	89 ca                	mov    edx,ecx
   140003b41:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b45:	88 10                	mov    BYTE PTR [rax],dl
   140003b47:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b4b:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b4e:	3c 39                	cmp    al,0x39
   140003b50:	7e 1a                	jle    140003b6c <__pformat_xint+0x11e>
   140003b52:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b56:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003b59:	83 c0 07             	add    eax,0x7
   140003b5c:	89 c2                	mov    edx,eax
   140003b5e:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140003b61:	83 e0 20             	and    eax,0x20
   140003b64:	09 c2                	or     edx,eax
   140003b66:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140003b6a:	88 10                	mov    BYTE PTR [rax],dl
   140003b6c:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140003b70:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003b73:	89 c1                	mov    ecx,eax
   140003b75:	48 d3 ea             	shr    rdx,cl
   140003b78:	48 89 d0             	mov    rax,rdx
   140003b7b:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140003b7f:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   140003b83:	48 85 c0             	test   rax,rax
   140003b86:	75 99                	jne    140003b21 <__pformat_xint+0xd3>
   140003b88:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003b8c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003b90:	75 13                	jne    140003ba5 <__pformat_xint+0x157>
   140003b92:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003b96:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003b99:	80 e4 f7             	and    ah,0xf7
   140003b9c:	89 c2                	mov    edx,eax
   140003b9e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ba2:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140003ba5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ba9:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003bac:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003baf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bb3:	7e 3a                	jle    140003bef <__pformat_xint+0x1a1>
   140003bb5:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140003bb8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bbc:	48 2b 45 e0          	sub    rax,QWORD PTR [rbp-0x20]
   140003bc0:	89 c1                	mov    ecx,eax
   140003bc2:	89 d0                	mov    eax,edx
   140003bc4:	29 c8                	sub    eax,ecx
   140003bc6:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003bc9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003bcd:	7e 20                	jle    140003bef <__pformat_xint+0x1a1>
   140003bcf:	eb 0f                	jmp    140003be0 <__pformat_xint+0x192>
   140003bd1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003bd5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003bd9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003bdd:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003be0:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003be3:	8d 50 ff             	lea    edx,[rax-0x1]
   140003be6:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003be9:	85 c0                	test   eax,eax
   140003beb:	7f e4                	jg     140003bd1 <__pformat_xint+0x183>
   140003bed:	eb 25                	jmp    140003c14 <__pformat_xint+0x1c6>
   140003bef:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003bf3:	75 1f                	jne    140003c14 <__pformat_xint+0x1c6>
   140003bf5:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003bf9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003bfc:	25 00 08 00 00       	and    eax,0x800
   140003c01:	85 c0                	test   eax,eax
   140003c03:	74 0f                	je     140003c14 <__pformat_xint+0x1c6>
   140003c05:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c09:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c0d:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c11:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c14:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c18:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140003c1c:	75 1a                	jne    140003c38 <__pformat_xint+0x1ea>
   140003c1e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c22:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003c25:	85 c0                	test   eax,eax
   140003c27:	74 0f                	je     140003c38 <__pformat_xint+0x1ea>
   140003c29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003c2d:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003c31:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003c35:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003c38:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c3c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c3f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140003c43:	48 2b 55 e0          	sub    rdx,QWORD PTR [rbp-0x20]
   140003c47:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003c4a:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140003c4d:	7d 15                	jge    140003c64 <__pformat_xint+0x216>
   140003c4f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c53:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c56:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140003c59:	89 c2                	mov    edx,eax
   140003c5b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c5f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140003c62:	eb 0b                	jmp    140003c6f <__pformat_xint+0x221>
   140003c64:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c68:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140003c6f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c73:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140003c76:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003c79:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c7d:	7e 1a                	jle    140003c99 <__pformat_xint+0x24b>
   140003c7f:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003c83:	74 14                	je     140003c99 <__pformat_xint+0x24b>
   140003c85:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003c89:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003c8c:	25 00 08 00 00       	and    eax,0x800
   140003c91:	85 c0                	test   eax,eax
   140003c93:	74 04                	je     140003c99 <__pformat_xint+0x24b>
   140003c95:	83 6d fc 02          	sub    DWORD PTR [rbp-0x4],0x2
   140003c99:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003c9d:	7e 3c                	jle    140003cdb <__pformat_xint+0x28d>
   140003c9f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ca3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140003ca6:	85 c0                	test   eax,eax
   140003ca8:	79 31                	jns    140003cdb <__pformat_xint+0x28d>
   140003caa:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003cae:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003cb1:	25 00 06 00 00       	and    eax,0x600
   140003cb6:	3d 00 02 00 00       	cmp    eax,0x200
   140003cbb:	75 1e                	jne    140003cdb <__pformat_xint+0x28d>
   140003cbd:	eb 0f                	jmp    140003cce <__pformat_xint+0x280>
   140003cbf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cc3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cc7:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003ccb:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003cce:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003cd1:	8d 50 ff             	lea    edx,[rax-0x1]
   140003cd4:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003cd7:	85 c0                	test   eax,eax
   140003cd9:	7f e4                	jg     140003cbf <__pformat_xint+0x271>
   140003cdb:	83 7d 20 6f          	cmp    DWORD PTR [rbp+0x20],0x6f
   140003cdf:	74 30                	je     140003d11 <__pformat_xint+0x2c3>
   140003ce1:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003ce5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003ce8:	25 00 08 00 00       	and    eax,0x800
   140003ced:	85 c0                	test   eax,eax
   140003cef:	74 20                	je     140003d11 <__pformat_xint+0x2c3>
   140003cf1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003cf5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003cf9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003cfd:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003d00:	88 10                	mov    BYTE PTR [rax],dl
   140003d02:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d06:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140003d0a:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140003d0e:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140003d11:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140003d15:	7e 4c                	jle    140003d63 <__pformat_xint+0x315>
   140003d17:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d1b:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140003d1e:	25 00 04 00 00       	and    eax,0x400
   140003d23:	85 c0                	test   eax,eax
   140003d25:	75 3c                	jne    140003d63 <__pformat_xint+0x315>
   140003d27:	eb 11                	jmp    140003d3a <__pformat_xint+0x2ec>
   140003d29:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d2d:	48 89 c2             	mov    rdx,rax
   140003d30:	b9 20 00 00 00       	mov    ecx,0x20
   140003d35:	e8 26 f5 ff ff       	call   140003260 <__pformat_putc>
   140003d3a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d3d:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d40:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d43:	85 c0                	test   eax,eax
   140003d45:	7f e2                	jg     140003d29 <__pformat_xint+0x2db>
   140003d47:	eb 1a                	jmp    140003d63 <__pformat_xint+0x315>
   140003d49:	48 83 6d f0 01       	sub    QWORD PTR [rbp-0x10],0x1
   140003d4e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d52:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140003d55:	0f be c0             	movsx  eax,al
   140003d58:	48 8b 55 30          	mov    rdx,QWORD PTR [rbp+0x30]
   140003d5c:	89 c1                	mov    ecx,eax
   140003d5e:	e8 fd f4 ff ff       	call   140003260 <__pformat_putc>
   140003d63:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003d67:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140003d6b:	72 dc                	jb     140003d49 <__pformat_xint+0x2fb>
   140003d6d:	eb 11                	jmp    140003d80 <__pformat_xint+0x332>
   140003d6f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140003d73:	48 89 c2             	mov    rdx,rax
   140003d76:	b9 20 00 00 00       	mov    ecx,0x20
   140003d7b:	e8 e0 f4 ff ff       	call   140003260 <__pformat_putc>
   140003d80:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003d83:	8d 50 ff             	lea    edx,[rax-0x1]
   140003d86:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   140003d89:	85 c0                	test   eax,eax
   140003d8b:	7f e2                	jg     140003d6f <__pformat_xint+0x321>
   140003d8d:	90                   	nop
   140003d8e:	90                   	nop
   140003d8f:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   140003d93:	5b                   	pop    rbx
   140003d94:	5d                   	pop    rbp
   140003d95:	c3                   	ret

0000000140003d96 <init_fpreg_ldouble>:
   140003d96:	55                   	push   rbp
   140003d97:	53                   	push   rbx
   140003d98:	48 83 ec 28          	sub    rsp,0x28
   140003d9c:	48 8d 6c 24 20       	lea    rbp,[rsp+0x20]
   140003da1:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003da5:	48 89 d3             	mov    rbx,rdx
   140003da8:	db 2b                	fld    TBYTE PTR [rbx]
   140003daa:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003dad:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140003db0:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003db3:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
   140003db7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140003dbb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140003dbf:	48 89 01             	mov    QWORD PTR [rcx],rax
   140003dc2:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
   140003dc6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003dca:	48 83 c4 28          	add    rsp,0x28
   140003dce:	5b                   	pop    rbx
   140003dcf:	5d                   	pop    rbp
   140003dd0:	c3                   	ret

0000000140003dd1 <__pformat_cvt>:
   140003dd1:	55                   	push   rbp
   140003dd2:	53                   	push   rbx
   140003dd3:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140003dda:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140003de1:	00 
   140003de2:	89 4d 20             	mov    DWORD PTR [rbp+0x20],ecx
   140003de5:	48 89 d3             	mov    rbx,rdx
   140003de8:	db 2b                	fld    TBYTE PTR [rbx]
   140003dea:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140003ded:	44 89 45 30          	mov    DWORD PTR [rbp+0x30],r8d
   140003df1:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003df5:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140003dfc:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003e00:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003e03:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003e06:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140003e0a:	48 89 c1             	mov    rcx,rax
   140003e0d:	e8 84 ff ff ff       	call   140003d96 <init_fpreg_ldouble>
   140003e12:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140003e15:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140003e18:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140003e1c:	48 89 c1             	mov    rcx,rax
   140003e1f:	e8 9c 4e 00 00       	call   140008cc0 <__fpclassifyl>
   140003e24:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003e27:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e2a:	25 00 01 00 00       	and    eax,0x100
   140003e2f:	85 c0                	test   eax,eax
   140003e31:	74 1d                	je     140003e50 <__pformat_cvt+0x7f>
   140003e33:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e36:	25 00 04 00 00       	and    eax,0x400
   140003e3b:	85 c0                	test   eax,eax
   140003e3d:	74 07                	je     140003e46 <__pformat_cvt+0x75>
   140003e3f:	b8 03 00 00 00       	mov    eax,0x3
   140003e44:	eb 05                	jmp    140003e4b <__pformat_cvt+0x7a>
   140003e46:	b8 04 00 00 00       	mov    eax,0x4
   140003e4b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140003e4e:	eb 4a                	jmp    140003e9a <__pformat_cvt+0xc9>
   140003e50:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e53:	25 00 04 00 00       	and    eax,0x400
   140003e58:	85 c0                	test   eax,eax
   140003e5a:	74 37                	je     140003e93 <__pformat_cvt+0xc2>
   140003e5c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e5f:	25 00 40 00 00       	and    eax,0x4000
   140003e64:	85 c0                	test   eax,eax
   140003e66:	74 10                	je     140003e78 <__pformat_cvt+0xa7>
   140003e68:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140003e6f:	c7 45 fc c3 bf ff ff 	mov    DWORD PTR [rbp-0x4],0xffffbfc3
   140003e76:	eb 22                	jmp    140003e9a <__pformat_cvt+0xc9>
   140003e78:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140003e7f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003e83:	98                   	cwde
   140003e84:	25 ff 7f 00 00       	and    eax,0x7fff
   140003e89:	2d 3e 40 00 00       	sub    eax,0x403e
   140003e8e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140003e91:	eb 07                	jmp    140003e9a <__pformat_cvt+0xc9>
   140003e93:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140003e9a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140003e9d:	83 f8 04             	cmp    eax,0x4
   140003ea0:	74 0e                	je     140003eb0 <__pformat_cvt+0xdf>
   140003ea2:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140003ea6:	98                   	cwde
   140003ea7:	25 00 80 00 00       	and    eax,0x8000
   140003eac:	89 c2                	mov    edx,eax
   140003eae:	eb 05                	jmp    140003eb5 <__pformat_cvt+0xe4>
   140003eb0:	ba 00 00 00 00       	mov    edx,0x0
   140003eb5:	48 8b 45 40          	mov    rax,QWORD PTR [rbp+0x40]
   140003eb9:	89 10                	mov    DWORD PTR [rax],edx
   140003ebb:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140003ebe:	4c 8d 4d f8          	lea    r9,[rbp-0x8]
   140003ec2:	4c 8d 45 e0          	lea    r8,[rbp-0x20]
   140003ec6:	48 8d 0d a3 61 00 00 	lea    rcx,[rip+0x61a3]        # 14000a070 <fpi.0>
   140003ecd:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
   140003ed1:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140003ed6:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003eda:	48 89 54 24 30       	mov    QWORD PTR [rsp+0x30],rdx
   140003edf:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   140003ee2:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   140003ee6:	8b 55 20             	mov    edx,DWORD PTR [rbp+0x20]
   140003ee9:	89 54 24 20          	mov    DWORD PTR [rsp+0x20],edx
   140003eed:	89 c2                	mov    edx,eax
   140003eef:	e8 96 24 00 00       	call   14000638a <__gdtoa>
   140003ef4:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140003efb:	5b                   	pop    rbx
   140003efc:	5d                   	pop    rbp
   140003efd:	c3                   	ret

0000000140003efe <__pformat_ecvt>:
   140003efe:	55                   	push   rbp
   140003eff:	53                   	push   rbx
   140003f00:	48 83 ec 58          	sub    rsp,0x58
   140003f04:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003f09:	48 89 cb             	mov    rbx,rcx
   140003f0c:	db 2b                	fld    TBYTE PTR [rbx]
   140003f0e:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f11:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f14:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f18:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f1c:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f1f:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f22:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f26:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f29:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f2d:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f31:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f36:	4d 89 c1             	mov    r9,r8
   140003f39:	41 89 c8             	mov    r8d,ecx
   140003f3c:	48 89 c2             	mov    rdx,rax
   140003f3f:	b9 02 00 00 00       	mov    ecx,0x2
   140003f44:	e8 88 fe ff ff       	call   140003dd1 <__pformat_cvt>
   140003f49:	48 83 c4 58          	add    rsp,0x58
   140003f4d:	5b                   	pop    rbx
   140003f4e:	5d                   	pop    rbp
   140003f4f:	c3                   	ret

0000000140003f50 <__pformat_fcvt>:
   140003f50:	55                   	push   rbp
   140003f51:	53                   	push   rbx
   140003f52:	48 83 ec 58          	sub    rsp,0x58
   140003f56:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140003f5b:	48 89 cb             	mov    rbx,rcx
   140003f5e:	db 2b                	fld    TBYTE PTR [rbx]
   140003f60:	db 7d f0             	fstp   TBYTE PTR [rbp-0x10]
   140003f63:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140003f66:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140003f6a:	4c 89 4d 38          	mov    QWORD PTR [rbp+0x38],r9
   140003f6e:	db 6d f0             	fld    TBYTE PTR [rbp-0x10]
   140003f71:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140003f74:	4c 8b 45 30          	mov    r8,QWORD PTR [rbp+0x30]
   140003f78:	8b 4d 28             	mov    ecx,DWORD PTR [rbp+0x28]
   140003f7b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140003f7f:	48 8b 55 38          	mov    rdx,QWORD PTR [rbp+0x38]
   140003f83:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   140003f88:	4d 89 c1             	mov    r9,r8
   140003f8b:	41 89 c8             	mov    r8d,ecx
   140003f8e:	48 89 c2             	mov    rdx,rax
   140003f91:	b9 03 00 00 00       	mov    ecx,0x3
   140003f96:	e8 36 fe ff ff       	call   140003dd1 <__pformat_cvt>
   140003f9b:	48 83 c4 58          	add    rsp,0x58
   140003f9f:	5b                   	pop    rbx
   140003fa0:	5d                   	pop    rbp
   140003fa1:	c3                   	ret

0000000140003fa2 <__pformat_emit_radix_point>:
   140003fa2:	55                   	push   rbp
   140003fa3:	53                   	push   rbx
   140003fa4:	48 83 ec 68          	sub    rsp,0x68
   140003fa8:	48 8d 6c 24 60       	lea    rbp,[rsp+0x60]
   140003fad:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   140003fb1:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fb5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140003fb8:	83 f8 fd             	cmp    eax,0xfffffffd
   140003fbb:	75 48                	jne    140004005 <__pformat_emit_radix_point+0x63>
   140003fbd:	48 c7 45 cc 00 00 00 	mov    QWORD PTR [rbp-0x34],0x0
   140003fc4:	00 
   140003fc5:	e8 4e 57 00 00       	call   140009718 <localeconv>
   140003fca:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   140003fcd:	48 8d 4d cc          	lea    rcx,[rbp-0x34]
   140003fd1:	48 8d 45 d6          	lea    rax,[rbp-0x2a]
   140003fd5:	49 89 c9             	mov    r9,rcx
   140003fd8:	41 b8 10 00 00 00    	mov    r8d,0x10
   140003fde:	48 89 c1             	mov    rcx,rax
   140003fe1:	e8 6a 51 00 00       	call   140009150 <mbrtowc>
   140003fe6:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140003fe9:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   140003fed:	7e 0c                	jle    140003ffb <__pformat_emit_radix_point+0x59>
   140003fef:	0f b7 55 d6          	movzx  edx,WORD PTR [rbp-0x2a]
   140003ff3:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003ff7:	66 89 50 18          	mov    WORD PTR [rax+0x18],dx
   140003ffb:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140003fff:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140004002:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140004005:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004009:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   14000400d:	66 85 c0             	test   ax,ax
   140004010:	0f 84 b8 00 00 00    	je     1400040ce <__pformat_emit_radix_point+0x12c>
   140004016:	48 89 e0             	mov    rax,rsp
   140004019:	48 89 c3             	mov    rbx,rax
   14000401c:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004020:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140004023:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004026:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004029:	48 63 d0             	movsxd rdx,eax
   14000402c:	48 83 ea 01          	sub    rdx,0x1
   140004030:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140004034:	48 98                	cdqe
   140004036:	48 83 c0 0f          	add    rax,0xf
   14000403a:	48 c1 e8 04          	shr    rax,0x4
   14000403e:	48 c1 e0 04          	shl    rax,0x4
   140004042:	e8 59 f1 ff ff       	call   1400031a0 <___chkstk_ms>
   140004047:	48 29 c4             	sub    rsp,rax
   14000404a:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
   14000404f:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140004053:	48 c7 45 c4 00 00 00 	mov    QWORD PTR [rbp-0x3c],0x0
   14000405a:	00 
   14000405b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000405f:	0f b7 40 18          	movzx  eax,WORD PTR [rax+0x18]
   140004063:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
   140004067:	0f b7 d0             	movzx  edx,ax
   14000406a:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000406e:	49 89 c8             	mov    r8,rcx
   140004071:	48 89 c1             	mov    rcx,rax
   140004074:	e8 87 50 00 00       	call   140009100 <wcrtomb>
   140004079:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000407c:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004080:	7e 36                	jle    1400040b8 <__pformat_emit_radix_point+0x116>
   140004082:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140004086:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000408a:	eb 1d                	jmp    1400040a9 <__pformat_emit_radix_point+0x107>
   14000408c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004090:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004094:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004098:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000409b:	0f be c0             	movsx  eax,al
   14000409e:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400040a2:	89 c1                	mov    ecx,eax
   1400040a4:	e8 b7 f1 ff ff       	call   140003260 <__pformat_putc>
   1400040a9:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400040ac:	8d 50 ff             	lea    edx,[rax-0x1]
   1400040af:	89 55 fc             	mov    DWORD PTR [rbp-0x4],edx
   1400040b2:	85 c0                	test   eax,eax
   1400040b4:	7f d6                	jg     14000408c <__pformat_emit_radix_point+0xea>
   1400040b6:	eb 11                	jmp    1400040c9 <__pformat_emit_radix_point+0x127>
   1400040b8:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040bc:	48 89 c2             	mov    rdx,rax
   1400040bf:	b9 2e 00 00 00       	mov    ecx,0x2e
   1400040c4:	e8 97 f1 ff ff       	call   140003260 <__pformat_putc>
   1400040c9:	48 89 dc             	mov    rsp,rbx
   1400040cc:	eb 11                	jmp    1400040df <__pformat_emit_radix_point+0x13d>
   1400040ce:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400040d2:	48 89 c2             	mov    rdx,rax
   1400040d5:	b9 2e 00 00 00       	mov    ecx,0x2e
   1400040da:	e8 81 f1 ff ff       	call   140003260 <__pformat_putc>
   1400040df:	90                   	nop
   1400040e0:	48 8d 65 08          	lea    rsp,[rbp+0x8]
   1400040e4:	5b                   	pop    rbx
   1400040e5:	5d                   	pop    rbp
   1400040e6:	c3                   	ret

00000001400040e7 <__pformat_emit_numeric_value>:
   1400040e7:	55                   	push   rbp
   1400040e8:	48 89 e5             	mov    rbp,rsp
   1400040eb:	48 83 ec 30          	sub    rsp,0x30
   1400040ef:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400040f2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400040f6:	83 7d 10 2e          	cmp    DWORD PTR [rbp+0x10],0x2e
   1400040fa:	75 0e                	jne    14000410a <__pformat_emit_numeric_value+0x23>
   1400040fc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004100:	48 89 c1             	mov    rcx,rax
   140004103:	e8 9a fe ff ff       	call   140003fa2 <__pformat_emit_radix_point>
   140004108:	eb 43                	jmp    14000414d <__pformat_emit_numeric_value+0x66>
   14000410a:	83 7d 10 2c          	cmp    DWORD PTR [rbp+0x10],0x2c
   14000410e:	75 2f                	jne    14000413f <__pformat_emit_numeric_value+0x58>
   140004110:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140004114:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   140004118:	66 89 45 fe          	mov    WORD PTR [rbp-0x2],ax
   14000411c:	0f b7 45 fe          	movzx  eax,WORD PTR [rbp-0x2]
   140004120:	66 85 c0             	test   ax,ax
   140004123:	74 28                	je     14000414d <__pformat_emit_numeric_value+0x66>
   140004125:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004129:	48 8d 45 fe          	lea    rax,[rbp-0x2]
   14000412d:	49 89 d0             	mov    r8,rdx
   140004130:	ba 01 00 00 00       	mov    edx,0x1
   140004135:	48 89 c1             	mov    rcx,rax
   140004138:	e8 2c f3 ff ff       	call   140003469 <__pformat_wputchars>
   14000413d:	eb 0e                	jmp    14000414d <__pformat_emit_numeric_value+0x66>
   14000413f:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140004143:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140004146:	89 c1                	mov    ecx,eax
   140004148:	e8 13 f1 ff ff       	call   140003260 <__pformat_putc>
   14000414d:	90                   	nop
   14000414e:	48 83 c4 30          	add    rsp,0x30
   140004152:	5d                   	pop    rbp
   140004153:	c3                   	ret

0000000140004154 <__pformat_emit_inf_or_nan>:
   140004154:	55                   	push   rbp
   140004155:	48 89 e5             	mov    rbp,rsp
   140004158:	48 83 ec 40          	sub    rsp,0x40
   14000415c:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000415f:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004163:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140004167:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000416b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000416f:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004173:	c7 40 10 ff ff ff ff 	mov    DWORD PTR [rax+0x10],0xffffffff
   14000417a:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   14000417e:	74 11                	je     140004191 <__pformat_emit_inf_or_nan+0x3d>
   140004180:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140004184:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004188:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000418c:	c6 00 2d             	mov    BYTE PTR [rax],0x2d
   14000418f:	eb 3e                	jmp    1400041cf <__pformat_emit_inf_or_nan+0x7b>
   140004191:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140004195:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004198:	25 00 01 00 00       	and    eax,0x100
   14000419d:	85 c0                	test   eax,eax
   14000419f:	74 11                	je     1400041b2 <__pformat_emit_inf_or_nan+0x5e>
   1400041a1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041a5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041a9:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041ad:	c6 00 2b             	mov    BYTE PTR [rax],0x2b
   1400041b0:	eb 1d                	jmp    1400041cf <__pformat_emit_inf_or_nan+0x7b>
   1400041b2:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400041b6:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041b9:	83 e0 40             	and    eax,0x40
   1400041bc:	85 c0                	test   eax,eax
   1400041be:	74 0f                	je     1400041cf <__pformat_emit_inf_or_nan+0x7b>
   1400041c0:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041c4:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041c8:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400041cc:	c6 00 20             	mov    BYTE PTR [rax],0x20
   1400041cf:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   1400041d6:	eb 38                	jmp    140004210 <__pformat_emit_inf_or_nan+0xbc>
   1400041d8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400041dc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400041e0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400041e4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400041e7:	83 e0 df             	and    eax,0xffffffdf
   1400041ea:	41 89 c0             	mov    r8d,eax
   1400041ed:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400041f1:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400041f4:	83 e0 20             	and    eax,0x20
   1400041f7:	89 c1                	mov    ecx,eax
   1400041f9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400041fd:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004201:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140004205:	44 89 c2             	mov    edx,r8d
   140004208:	09 ca                	or     edx,ecx
   14000420a:	88 10                	mov    BYTE PTR [rax],dl
   14000420c:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004210:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004214:	7f c2                	jg     1400041d8 <__pformat_emit_inf_or_nan+0x84>
   140004216:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000421a:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   14000421e:	48 29 c2             	sub    rdx,rax
   140004221:	89 d1                	mov    ecx,edx
   140004223:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140004227:	48 8d 45 ec          	lea    rax,[rbp-0x14]
   14000422b:	49 89 d0             	mov    r8,rdx
   14000422e:	89 ca                	mov    edx,ecx
   140004230:	48 89 c1             	mov    rcx,rax
   140004233:	e8 ac f0 ff ff       	call   1400032e4 <__pformat_putchars>
   140004238:	90                   	nop
   140004239:	48 83 c4 40          	add    rsp,0x40
   14000423d:	5d                   	pop    rbp
   14000423e:	c3                   	ret

000000014000423f <__pformat_emit_float>:
   14000423f:	55                   	push   rbp
   140004240:	48 89 e5             	mov    rbp,rsp
   140004243:	48 83 ec 30          	sub    rsp,0x30
   140004247:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000424a:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000424e:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140004252:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004256:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000425a:	7e 2e                	jle    14000428a <__pformat_emit_float+0x4b>
   14000425c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004260:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004263:	39 45 20             	cmp    DWORD PTR [rbp+0x20],eax
   140004266:	7f 15                	jg     14000427d <__pformat_emit_float+0x3e>
   140004268:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000426c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000426f:	2b 45 20             	sub    eax,DWORD PTR [rbp+0x20]
   140004272:	89 c2                	mov    edx,eax
   140004274:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004278:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000427b:	eb 29                	jmp    1400042a6 <__pformat_emit_float+0x67>
   14000427d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004281:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004288:	eb 1c                	jmp    1400042a6 <__pformat_emit_float+0x67>
   14000428a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000428e:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004291:	85 c0                	test   eax,eax
   140004293:	7e 11                	jle    1400042a6 <__pformat_emit_float+0x67>
   140004295:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004299:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000429c:	8d 50 ff             	lea    edx,[rax-0x1]
   14000429f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042a3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042aa:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042ad:	85 c0                	test   eax,eax
   1400042af:	78 2b                	js     1400042dc <__pformat_emit_float+0x9d>
   1400042b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042b5:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400042b8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042bc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042bf:	39 c2                	cmp    edx,eax
   1400042c1:	7e 19                	jle    1400042dc <__pformat_emit_float+0x9d>
   1400042c3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042c7:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   1400042ca:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042ce:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042d1:	29 c2                	sub    edx,eax
   1400042d3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042d7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400042da:	eb 0b                	jmp    1400042e7 <__pformat_emit_float+0xa8>
   1400042dc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042e0:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400042e7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042eb:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400042ee:	85 c0                	test   eax,eax
   1400042f0:	7e 2c                	jle    14000431e <__pformat_emit_float+0xdf>
   1400042f2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400042f6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400042f9:	85 c0                	test   eax,eax
   1400042fb:	7f 10                	jg     14000430d <__pformat_emit_float+0xce>
   1400042fd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004301:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004304:	25 00 08 00 00       	and    eax,0x800
   140004309:	85 c0                	test   eax,eax
   14000430b:	74 11                	je     14000431e <__pformat_emit_float+0xdf>
   14000430d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004311:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004314:	8d 50 ff             	lea    edx,[rax-0x1]
   140004317:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000431b:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   14000431e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004322:	7e 64                	jle    140004388 <__pformat_emit_float+0x149>
   140004324:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004328:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000432b:	25 00 10 00 00       	and    eax,0x1000
   140004330:	85 c0                	test   eax,eax
   140004332:	74 54                	je     140004388 <__pformat_emit_float+0x149>
   140004334:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004338:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   14000433c:	66 85 c0             	test   ax,ax
   14000433f:	74 47                	je     140004388 <__pformat_emit_float+0x149>
   140004341:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004344:	83 c0 02             	add    eax,0x2
   140004347:	48 63 d0             	movsxd rdx,eax
   14000434a:	48 69 d2 56 55 55 55 	imul   rdx,rdx,0x55555556
   140004351:	48 c1 ea 20          	shr    rdx,0x20
   140004355:	c1 f8 1f             	sar    eax,0x1f
   140004358:	29 c2                	sub    edx,eax
   14000435a:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000435d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004360:	eb 15                	jmp    140004377 <__pformat_emit_float+0x138>
   140004362:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140004366:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000436a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000436d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004370:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004374:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004377:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000437b:	7e 0b                	jle    140004388 <__pformat_emit_float+0x149>
   14000437d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004381:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004384:	85 c0                	test   eax,eax
   140004386:	7f da                	jg     140004362 <__pformat_emit_float+0x123>
   140004388:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000438c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000438f:	85 c0                	test   eax,eax
   140004391:	7e 27                	jle    1400043ba <__pformat_emit_float+0x17b>
   140004393:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004397:	75 10                	jne    1400043a9 <__pformat_emit_float+0x16a>
   140004399:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000439d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043a0:	25 c0 01 00 00       	and    eax,0x1c0
   1400043a5:	85 c0                	test   eax,eax
   1400043a7:	74 11                	je     1400043ba <__pformat_emit_float+0x17b>
   1400043a9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ad:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043b0:	8d 50 ff             	lea    edx,[rax-0x1]
   1400043b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043b7:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400043ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043be:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043c1:	85 c0                	test   eax,eax
   1400043c3:	7e 38                	jle    1400043fd <__pformat_emit_float+0x1be>
   1400043c5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043c9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400043cc:	25 00 06 00 00       	and    eax,0x600
   1400043d1:	85 c0                	test   eax,eax
   1400043d3:	75 28                	jne    1400043fd <__pformat_emit_float+0x1be>
   1400043d5:	eb 11                	jmp    1400043e8 <__pformat_emit_float+0x1a9>
   1400043d7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043db:	48 89 c2             	mov    rdx,rax
   1400043de:	b9 20 00 00 00       	mov    ecx,0x20
   1400043e3:	e8 78 ee ff ff       	call   140003260 <__pformat_putc>
   1400043e8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400043ec:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400043ef:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400043f2:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400043f6:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   1400043f9:	85 c0                	test   eax,eax
   1400043fb:	7f da                	jg     1400043d7 <__pformat_emit_float+0x198>
   1400043fd:	83 7d 10 00          	cmp    DWORD PTR [rbp+0x10],0x0
   140004401:	74 13                	je     140004416 <__pformat_emit_float+0x1d7>
   140004403:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004407:	48 89 c2             	mov    rdx,rax
   14000440a:	b9 2d 00 00 00       	mov    ecx,0x2d
   14000440f:	e8 4c ee ff ff       	call   140003260 <__pformat_putc>
   140004414:	eb 42                	jmp    140004458 <__pformat_emit_float+0x219>
   140004416:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000441a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000441d:	25 00 01 00 00       	and    eax,0x100
   140004422:	85 c0                	test   eax,eax
   140004424:	74 13                	je     140004439 <__pformat_emit_float+0x1fa>
   140004426:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000442a:	48 89 c2             	mov    rdx,rax
   14000442d:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004432:	e8 29 ee ff ff       	call   140003260 <__pformat_putc>
   140004437:	eb 1f                	jmp    140004458 <__pformat_emit_float+0x219>
   140004439:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000443d:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004440:	83 e0 40             	and    eax,0x40
   140004443:	85 c0                	test   eax,eax
   140004445:	74 11                	je     140004458 <__pformat_emit_float+0x219>
   140004447:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000444b:	48 89 c2             	mov    rdx,rax
   14000444e:	b9 20 00 00 00       	mov    ecx,0x20
   140004453:	e8 08 ee ff ff       	call   140003260 <__pformat_putc>
   140004458:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000445c:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   14000445f:	85 c0                	test   eax,eax
   140004461:	7e 3b                	jle    14000449e <__pformat_emit_float+0x25f>
   140004463:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004467:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000446a:	25 00 06 00 00       	and    eax,0x600
   14000446f:	3d 00 02 00 00       	cmp    eax,0x200
   140004474:	75 28                	jne    14000449e <__pformat_emit_float+0x25f>
   140004476:	eb 11                	jmp    140004489 <__pformat_emit_float+0x24a>
   140004478:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000447c:	48 89 c2             	mov    rdx,rax
   14000447f:	b9 30 00 00 00       	mov    ecx,0x30
   140004484:	e8 d7 ed ff ff       	call   140003260 <__pformat_putc>
   140004489:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000448d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004490:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004493:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004497:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   14000449a:	85 c0                	test   eax,eax
   14000449c:	7f da                	jg     140004478 <__pformat_emit_float+0x239>
   14000449e:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044a2:	0f 8e a7 00 00 00    	jle    14000454f <__pformat_emit_float+0x310>
   1400044a8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044ac:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044af:	84 c0                	test   al,al
   1400044b1:	74 14                	je     1400044c7 <__pformat_emit_float+0x288>
   1400044b3:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400044b7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400044bb:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400044bf:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400044c2:	0f be c0             	movsx  eax,al
   1400044c5:	eb 05                	jmp    1400044cc <__pformat_emit_float+0x28d>
   1400044c7:	b8 30 00 00 00       	mov    eax,0x30
   1400044cc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400044d0:	89 c1                	mov    ecx,eax
   1400044d2:	e8 89 ed ff ff       	call   140003260 <__pformat_putc>
   1400044d7:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   1400044db:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400044df:	74 62                	je     140004543 <__pformat_emit_float+0x304>
   1400044e1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044e5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400044e8:	25 00 10 00 00       	and    eax,0x1000
   1400044ed:	85 c0                	test   eax,eax
   1400044ef:	74 52                	je     140004543 <__pformat_emit_float+0x304>
   1400044f1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400044f5:	0f b7 40 20          	movzx  eax,WORD PTR [rax+0x20]
   1400044f9:	66 85 c0             	test   ax,ax
   1400044fc:	74 45                	je     140004543 <__pformat_emit_float+0x304>
   1400044fe:	8b 4d 20             	mov    ecx,DWORD PTR [rbp+0x20]
   140004501:	48 63 c1             	movsxd rax,ecx
   140004504:	48 69 c0 56 55 55 55 	imul   rax,rax,0x55555556
   14000450b:	48 c1 e8 20          	shr    rax,0x20
   14000450f:	48 89 c2             	mov    rdx,rax
   140004512:	89 c8                	mov    eax,ecx
   140004514:	c1 f8 1f             	sar    eax,0x1f
   140004517:	29 c2                	sub    edx,eax
   140004519:	89 d0                	mov    eax,edx
   14000451b:	01 c0                	add    eax,eax
   14000451d:	01 d0                	add    eax,edx
   14000451f:	29 c1                	sub    ecx,eax
   140004521:	89 ca                	mov    edx,ecx
   140004523:	85 d2                	test   edx,edx
   140004525:	75 1c                	jne    140004543 <__pformat_emit_float+0x304>
   140004527:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000452b:	48 83 c0 20          	add    rax,0x20
   14000452f:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004533:	49 89 d0             	mov    r8,rdx
   140004536:	ba 01 00 00 00       	mov    edx,0x1
   14000453b:	48 89 c1             	mov    rcx,rax
   14000453e:	e8 26 ef ff ff       	call   140003469 <__pformat_wputchars>
   140004543:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004547:	0f 8f 5b ff ff ff    	jg     1400044a8 <__pformat_emit_float+0x269>
   14000454d:	eb 11                	jmp    140004560 <__pformat_emit_float+0x321>
   14000454f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004553:	48 89 c2             	mov    rdx,rax
   140004556:	b9 30 00 00 00       	mov    ecx,0x30
   14000455b:	e8 00 ed ff ff       	call   140003260 <__pformat_putc>
   140004560:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004564:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004567:	85 c0                	test   eax,eax
   140004569:	7f 10                	jg     14000457b <__pformat_emit_float+0x33c>
   14000456b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000456f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004572:	25 00 08 00 00       	and    eax,0x800
   140004577:	85 c0                	test   eax,eax
   140004579:	74 0c                	je     140004587 <__pformat_emit_float+0x348>
   14000457b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000457f:	48 89 c1             	mov    rcx,rax
   140004582:	e8 1b fa ff ff       	call   140003fa2 <__pformat_emit_radix_point>
   140004587:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000458b:	79 5f                	jns    1400045ec <__pformat_emit_float+0x3ad>
   14000458d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004591:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004594:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004597:	01 c2                	add    edx,eax
   140004599:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000459d:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400045a0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045a4:	48 89 c2             	mov    rdx,rax
   1400045a7:	b9 30 00 00 00       	mov    ecx,0x30
   1400045ac:	e8 af ec ff ff       	call   140003260 <__pformat_putc>
   1400045b1:	83 45 20 01          	add    DWORD PTR [rbp+0x20],0x1
   1400045b5:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   1400045b9:	78 e5                	js     1400045a0 <__pformat_emit_float+0x361>
   1400045bb:	eb 2f                	jmp    1400045ec <__pformat_emit_float+0x3ad>
   1400045bd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400045c1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400045c4:	84 c0                	test   al,al
   1400045c6:	74 14                	je     1400045dc <__pformat_emit_float+0x39d>
   1400045c8:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400045cc:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400045d0:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400045d4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400045d7:	0f be c0             	movsx  eax,al
   1400045da:	eb 05                	jmp    1400045e1 <__pformat_emit_float+0x3a2>
   1400045dc:	b8 30 00 00 00       	mov    eax,0x30
   1400045e1:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045e5:	89 c1                	mov    ecx,eax
   1400045e7:	e8 74 ec ff ff       	call   140003260 <__pformat_putc>
   1400045ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400045f0:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400045f3:	8d 48 ff             	lea    ecx,[rax-0x1]
   1400045f6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400045fa:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   1400045fd:	85 c0                	test   eax,eax
   1400045ff:	7f bc                	jg     1400045bd <__pformat_emit_float+0x37e>
   140004601:	90                   	nop
   140004602:	90                   	nop
   140004603:	48 83 c4 30          	add    rsp,0x30
   140004607:	5d                   	pop    rbp
   140004608:	c3                   	ret

0000000140004609 <__pformat_emit_efloat>:
   140004609:	55                   	push   rbp
   14000460a:	48 89 e5             	mov    rbp,rsp
   14000460d:	48 83 ec 50          	sub    rsp,0x50
   140004611:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140004614:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140004618:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   14000461c:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140004620:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140004627:	83 6d 20 01          	sub    DWORD PTR [rbp+0x20],0x1
   14000462b:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   14000462f:	79 09                	jns    14000463a <__pformat_emit_efloat+0x31>
   140004631:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004638:	eb 05                	jmp    14000463f <__pformat_emit_efloat+0x36>
   14000463a:	b8 00 00 00 00       	mov    eax,0x0
   14000463f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140004643:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004646:	48 98                	cdqe
   140004648:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000464c:	eb 04                	jmp    140004652 <__pformat_emit_efloat+0x49>
   14000464e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140004652:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140004655:	48 63 d0             	movsxd rdx,eax
   140004658:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   14000465f:	48 c1 ea 20          	shr    rdx,0x20
   140004663:	89 d1                	mov    ecx,edx
   140004665:	c1 f9 02             	sar    ecx,0x2
   140004668:	99                   	cdq
   140004669:	89 c8                	mov    eax,ecx
   14000466b:	29 d0                	sub    eax,edx
   14000466d:	89 45 20             	mov    DWORD PTR [rbp+0x20],eax
   140004670:	83 7d 20 00          	cmp    DWORD PTR [rbp+0x20],0x0
   140004674:	75 d8                	jne    14000464e <__pformat_emit_efloat+0x45>
   140004676:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000467a:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   14000467d:	83 f8 ff             	cmp    eax,0xffffffff
   140004680:	75 0b                	jne    14000468d <__pformat_emit_efloat+0x84>
   140004682:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004686:	c7 40 2c 02 00 00 00 	mov    DWORD PTR [rax+0x2c],0x2
   14000468d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004691:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   140004694:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140004697:	7d 0a                	jge    1400046a3 <__pformat_emit_efloat+0x9a>
   140004699:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000469d:	8b 40 2c             	mov    eax,DWORD PTR [rax+0x2c]
   1400046a0:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400046a3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046a7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046aa:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400046ae:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   1400046b1:	7d 15                	jge    1400046c8 <__pformat_emit_efloat+0xbf>
   1400046b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046b7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400046ba:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   1400046bd:	89 c2                	mov    edx,eax
   1400046bf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046c3:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   1400046c6:	eb 0b                	jmp    1400046d3 <__pformat_emit_efloat+0xca>
   1400046c8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046cc:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   1400046d3:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400046d7:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400046db:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   1400046de:	49 89 c9             	mov    r9,rcx
   1400046e1:	41 b8 01 00 00 00    	mov    r8d,0x1
   1400046e7:	89 c1                	mov    ecx,eax
   1400046e9:	e8 51 fb ff ff       	call   14000423f <__pformat_emit_float>
   1400046ee:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046f2:	8b 50 2c             	mov    edx,DWORD PTR [rax+0x2c]
   1400046f5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400046f9:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400046fc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004700:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004703:	0d c0 01 00 00       	or     eax,0x1c0
   140004708:	89 c2                	mov    edx,eax
   14000470a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000470e:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004711:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004715:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004718:	83 e0 20             	and    eax,0x20
   14000471b:	83 c8 45             	or     eax,0x45
   14000471e:	89 c1                	mov    ecx,eax
   140004720:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004724:	48 89 c2             	mov    rdx,rax
   140004727:	e8 34 eb ff ff       	call   140003260 <__pformat_putc>
   14000472c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004730:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004733:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140004736:	83 ea 01             	sub    edx,0x1
   140004739:	01 c2                	add    edx,eax
   14000473b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000473f:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004742:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140004746:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   14000474a:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   14000474e:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140004752:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004756:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   14000475a:	48 89 c1             	mov    rcx,rax
   14000475d:	e8 69 ef ff ff       	call   1400036cb <__pformat_int>
   140004762:	90                   	nop
   140004763:	48 83 c4 50          	add    rsp,0x50
   140004767:	5d                   	pop    rbp
   140004768:	c3                   	ret

0000000140004769 <__pformat_float>:
   140004769:	55                   	push   rbp
   14000476a:	53                   	push   rbx
   14000476b:	48 83 ec 58          	sub    rsp,0x58
   14000476f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004774:	48 89 cb             	mov    rbx,rcx
   140004777:	db 2b                	fld    TBYTE PTR [rbx]
   140004779:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000477c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004780:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004784:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004787:	85 c0                	test   eax,eax
   140004789:	79 0b                	jns    140004796 <__pformat_float+0x2d>
   14000478b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000478f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004796:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000479a:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000479d:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   1400047a0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400047a3:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   1400047a7:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400047ab:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   1400047af:	4d 89 c1             	mov    r9,r8
   1400047b2:	49 89 c8             	mov    r8,rcx
   1400047b5:	48 89 c1             	mov    rcx,rax
   1400047b8:	e8 93 f7 ff ff       	call   140003f50 <__pformat_fcvt>
   1400047bd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400047c1:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400047c4:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   1400047c9:	75 17                	jne    1400047e2 <__pformat_float+0x79>
   1400047cb:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047ce:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400047d2:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047d6:	49 89 c8             	mov    r8,rcx
   1400047d9:	89 c1                	mov    ecx,eax
   1400047db:	e8 74 f9 ff ff       	call   140004154 <__pformat_emit_inf_or_nan>
   1400047e0:	eb 43                	jmp    140004825 <__pformat_float+0xbc>
   1400047e2:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400047e5:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400047e8:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400047ec:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400047f0:	4d 89 c1             	mov    r9,r8
   1400047f3:	41 89 c8             	mov    r8d,ecx
   1400047f6:	89 c1                	mov    ecx,eax
   1400047f8:	e8 42 fa ff ff       	call   14000423f <__pformat_emit_float>
   1400047fd:	eb 11                	jmp    140004810 <__pformat_float+0xa7>
   1400047ff:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004803:	48 89 c2             	mov    rdx,rax
   140004806:	b9 20 00 00 00       	mov    ecx,0x20
   14000480b:	e8 50 ea ff ff       	call   140003260 <__pformat_putc>
   140004810:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004814:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004817:	8d 48 ff             	lea    ecx,[rax-0x1]
   14000481a:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   14000481e:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004821:	85 c0                	test   eax,eax
   140004823:	7f da                	jg     1400047ff <__pformat_float+0x96>
   140004825:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004829:	48 89 c1             	mov    rcx,rax
   14000482c:	e8 4e 17 00 00       	call   140005f7f <__freedtoa>
   140004831:	90                   	nop
   140004832:	48 83 c4 58          	add    rsp,0x58
   140004836:	5b                   	pop    rbx
   140004837:	5d                   	pop    rbp
   140004838:	c3                   	ret

0000000140004839 <__pformat_efloat>:
   140004839:	55                   	push   rbp
   14000483a:	53                   	push   rbx
   14000483b:	48 83 ec 58          	sub    rsp,0x58
   14000483f:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140004844:	48 89 cb             	mov    rbx,rcx
   140004847:	db 2b                	fld    TBYTE PTR [rbx]
   140004849:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   14000484c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004850:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004854:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004857:	85 c0                	test   eax,eax
   140004859:	79 0b                	jns    140004866 <__pformat_efloat+0x2d>
   14000485b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000485f:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004866:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000486a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000486d:	8d 50 01             	lea    edx,[rax+0x1]
   140004870:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004873:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004876:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000487a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000487e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004882:	4d 89 c1             	mov    r9,r8
   140004885:	49 89 c8             	mov    r8,rcx
   140004888:	48 89 c1             	mov    rcx,rax
   14000488b:	e8 6e f6 ff ff       	call   140003efe <__pformat_ecvt>
   140004890:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004894:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004897:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000489c:	75 17                	jne    1400048b5 <__pformat_efloat+0x7c>
   14000489e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048a1:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   1400048a5:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048a9:	49 89 c8             	mov    r8,rcx
   1400048ac:	89 c1                	mov    ecx,eax
   1400048ae:	e8 a1 f8 ff ff       	call   140004154 <__pformat_emit_inf_or_nan>
   1400048b3:	eb 1b                	jmp    1400048d0 <__pformat_efloat+0x97>
   1400048b5:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400048b8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400048bb:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400048bf:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400048c3:	4d 89 c1             	mov    r9,r8
   1400048c6:	41 89 c8             	mov    r8d,ecx
   1400048c9:	89 c1                	mov    ecx,eax
   1400048cb:	e8 39 fd ff ff       	call   140004609 <__pformat_emit_efloat>
   1400048d0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400048d4:	48 89 c1             	mov    rcx,rax
   1400048d7:	e8 a3 16 00 00       	call   140005f7f <__freedtoa>
   1400048dc:	90                   	nop
   1400048dd:	48 83 c4 58          	add    rsp,0x58
   1400048e1:	5b                   	pop    rbx
   1400048e2:	5d                   	pop    rbp
   1400048e3:	c3                   	ret

00000001400048e4 <__pformat_gfloat>:
   1400048e4:	55                   	push   rbp
   1400048e5:	53                   	push   rbx
   1400048e6:	48 83 ec 58          	sub    rsp,0x58
   1400048ea:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   1400048ef:	48 89 cb             	mov    rbx,rcx
   1400048f2:	db 2b                	fld    TBYTE PTR [rbx]
   1400048f4:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   1400048f7:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400048fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400048ff:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004902:	85 c0                	test   eax,eax
   140004904:	79 0d                	jns    140004913 <__pformat_gfloat+0x2f>
   140004906:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000490a:	c7 40 10 06 00 00 00 	mov    DWORD PTR [rax+0x10],0x6
   140004911:	eb 16                	jmp    140004929 <__pformat_gfloat+0x45>
   140004913:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004917:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   14000491a:	85 c0                	test   eax,eax
   14000491c:	75 0b                	jne    140004929 <__pformat_gfloat+0x45>
   14000491e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004922:	c7 40 10 01 00 00 00 	mov    DWORD PTR [rax+0x10],0x1
   140004929:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000492d:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   140004930:	db 6d e0             	fld    TBYTE PTR [rbp-0x20]
   140004933:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004936:	4c 8d 45 f4          	lea    r8,[rbp-0xc]
   14000493a:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   14000493e:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140004942:	4d 89 c1             	mov    r9,r8
   140004945:	49 89 c8             	mov    r8,rcx
   140004948:	48 89 c1             	mov    rcx,rax
   14000494b:	e8 ae f5 ff ff       	call   140003efe <__pformat_ecvt>
   140004950:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004954:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140004957:	3d 00 80 ff ff       	cmp    eax,0xffff8000
   14000495c:	75 1a                	jne    140004978 <__pformat_gfloat+0x94>
   14000495e:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004961:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004965:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004969:	49 89 c8             	mov    r8,rcx
   14000496c:	89 c1                	mov    ecx,eax
   14000496e:	e8 e1 f7 ff ff       	call   140004154 <__pformat_emit_inf_or_nan>
   140004973:	e9 14 01 00 00       	jmp    140004a8c <__pformat_gfloat+0x1a8>
   140004978:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000497b:	83 f8 fd             	cmp    eax,0xfffffffd
   14000497e:	0f 8c b2 00 00 00    	jl     140004a36 <__pformat_gfloat+0x152>
   140004984:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004988:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   14000498b:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000498e:	39 c2                	cmp    edx,eax
   140004990:	0f 8c a0 00 00 00    	jl     140004a36 <__pformat_gfloat+0x152>
   140004996:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000499a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000499d:	25 00 08 00 00       	and    eax,0x800
   1400049a2:	85 c0                	test   eax,eax
   1400049a4:	74 15                	je     1400049bb <__pformat_gfloat+0xd7>
   1400049a6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049aa:	8b 50 10             	mov    edx,DWORD PTR [rax+0x10]
   1400049ad:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400049b0:	29 c2                	sub    edx,eax
   1400049b2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049b6:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049b9:	eb 20                	jmp    1400049db <__pformat_gfloat+0xf7>
   1400049bb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400049bf:	48 89 c1             	mov    rcx,rax
   1400049c2:	e8 91 4d 00 00       	call   140009758 <strlen>
   1400049c7:	89 c1                	mov    ecx,eax
   1400049c9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   1400049cc:	89 c2                	mov    edx,eax
   1400049ce:	89 c8                	mov    eax,ecx
   1400049d0:	29 d0                	sub    eax,edx
   1400049d2:	89 c2                	mov    edx,eax
   1400049d4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049d8:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   1400049db:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049df:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400049e2:	85 c0                	test   eax,eax
   1400049e4:	79 0b                	jns    1400049f1 <__pformat_gfloat+0x10d>
   1400049e6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400049ea:	c7 40 10 00 00 00 00 	mov    DWORD PTR [rax+0x10],0x0
   1400049f1:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   1400049f4:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400049f7:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   1400049fb:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400049ff:	4d 89 c1             	mov    r9,r8
   140004a02:	41 89 c8             	mov    r8d,ecx
   140004a05:	89 c1                	mov    ecx,eax
   140004a07:	e8 33 f8 ff ff       	call   14000423f <__pformat_emit_float>
   140004a0c:	eb 11                	jmp    140004a1f <__pformat_gfloat+0x13b>
   140004a0e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a12:	48 89 c2             	mov    rdx,rax
   140004a15:	b9 20 00 00 00       	mov    ecx,0x20
   140004a1a:	e8 41 e8 ff ff       	call   140003260 <__pformat_putc>
   140004a1f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a23:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004a26:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004a29:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004a2d:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004a30:	85 c0                	test   eax,eax
   140004a32:	7f da                	jg     140004a0e <__pformat_gfloat+0x12a>
   140004a34:	eb 56                	jmp    140004a8c <__pformat_gfloat+0x1a8>
   140004a36:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a3a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004a3d:	25 00 08 00 00       	and    eax,0x800
   140004a42:	85 c0                	test   eax,eax
   140004a44:	74 13                	je     140004a59 <__pformat_gfloat+0x175>
   140004a46:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a4a:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004a4d:	8d 50 ff             	lea    edx,[rax-0x1]
   140004a50:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a54:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a57:	eb 18                	jmp    140004a71 <__pformat_gfloat+0x18d>
   140004a59:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a5d:	48 89 c1             	mov    rcx,rax
   140004a60:	e8 f3 4c 00 00       	call   140009758 <strlen>
   140004a65:	83 e8 01             	sub    eax,0x1
   140004a68:	89 c2                	mov    edx,eax
   140004a6a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004a6e:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004a71:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]
   140004a74:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140004a77:	4c 8b 45 28          	mov    r8,QWORD PTR [rbp+0x28]
   140004a7b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004a7f:	4d 89 c1             	mov    r9,r8
   140004a82:	41 89 c8             	mov    r8d,ecx
   140004a85:	89 c1                	mov    ecx,eax
   140004a87:	e8 7d fb ff ff       	call   140004609 <__pformat_emit_efloat>
   140004a8c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004a90:	48 89 c1             	mov    rcx,rax
   140004a93:	e8 e7 14 00 00       	call   140005f7f <__freedtoa>
   140004a98:	90                   	nop
   140004a99:	48 83 c4 58          	add    rsp,0x58
   140004a9d:	5b                   	pop    rbx
   140004a9e:	5d                   	pop    rbp
   140004a9f:	c3                   	ret

0000000140004aa0 <__pformat_emit_xfloat>:
   140004aa0:	55                   	push   rbp
   140004aa1:	53                   	push   rbx
   140004aa2:	48 81 ec 88 00 00 00 	sub    rsp,0x88
   140004aa9:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140004ab0:	00 
   140004ab1:	48 89 cb             	mov    rbx,rcx
   140004ab4:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004ab8:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004abc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140004ac0:	66 c7 45 f6 02 00    	mov    WORD PTR [rbp-0xa],0x2
   140004ac6:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004ac9:	48 85 c0             	test   rax,rax
   140004acc:	75 09                	jne    140004ad7 <__pformat_emit_xfloat+0x37>
   140004ace:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004ad2:	66 85 c0             	test   ax,ax
   140004ad5:	74 0b                	je     140004ae2 <__pformat_emit_xfloat+0x42>
   140004ad7:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004adb:	83 e8 03             	sub    eax,0x3
   140004ade:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004ae2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ae6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ae9:	85 c0                	test   eax,eax
   140004aeb:	0f 88 90 00 00 00    	js     140004b81 <__pformat_emit_xfloat+0xe1>
   140004af1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004af5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004af8:	83 f8 0e             	cmp    eax,0xe
   140004afb:	0f 8f 80 00 00 00    	jg     140004b81 <__pformat_emit_xfloat+0xe1>
   140004b01:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b04:	48 d1 e8             	shr    rax,1
   140004b07:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b0a:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b0d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b11:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b14:	b9 0e 00 00 00       	mov    ecx,0xe
   140004b19:	29 c1                	sub    ecx,eax
   140004b1b:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b22:	41 b8 04 00 00 00    	mov    r8d,0x4
   140004b28:	89 c1                	mov    ecx,eax
   140004b2a:	49 d3 e0             	shl    r8,cl
   140004b2d:	4c 89 c0             	mov    rax,r8
   140004b30:	48 01 d0             	add    rax,rdx
   140004b33:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b36:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b39:	48 85 c0             	test   rax,rax
   140004b3c:	78 0b                	js     140004b49 <__pformat_emit_xfloat+0xa9>
   140004b3e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b41:	48 01 c0             	add    rax,rax
   140004b44:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b47:	eb 15                	jmp    140004b5e <__pformat_emit_xfloat+0xbe>
   140004b49:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004b4d:	83 c0 04             	add    eax,0x4
   140004b50:	66 89 43 08          	mov    WORD PTR [rbx+0x8],ax
   140004b54:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b57:	48 c1 e8 03          	shr    rax,0x3
   140004b5b:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b5e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
   140004b61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b65:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b68:	b9 0f 00 00 00       	mov    ecx,0xf
   140004b6d:	29 c1                	sub    ecx,eax
   140004b6f:	8d 04 8d 00 00 00 00 	lea    eax,[rcx*4+0x0]
   140004b76:	89 c1                	mov    ecx,eax
   140004b78:	48 d3 ea             	shr    rdx,cl
   140004b7b:	48 89 d0             	mov    rax,rdx
   140004b7e:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004b81:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004b84:	48 85 c0             	test   rax,rax
   140004b87:	75 0f                	jne    140004b98 <__pformat_emit_xfloat+0xf8>
   140004b89:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b8d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b90:	85 c0                	test   eax,eax
   140004b92:	0f 8e f8 00 00 00    	jle    140004c90 <__pformat_emit_xfloat+0x1f0>
   140004b98:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004b9c:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004b9f:	83 f8 0e             	cmp    eax,0xe
   140004ba2:	7f 1a                	jg     140004bbe <__pformat_emit_xfloat+0x11e>
   140004ba4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ba8:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bab:	85 c0                	test   eax,eax
   140004bad:	78 0f                	js     140004bbe <__pformat_emit_xfloat+0x11e>
   140004baf:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bb3:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bb6:	83 c0 01             	add    eax,0x1
   140004bb9:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140004bbc:	eb 07                	jmp    140004bc5 <__pformat_emit_xfloat+0x125>
   140004bbe:	c7 45 f0 10 00 00 00 	mov    DWORD PTR [rbp-0x10],0x10
   140004bc5:	e9 bc 00 00 00       	jmp    140004c86 <__pformat_emit_xfloat+0x1e6>
   140004bca:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004bcd:	83 e0 0f             	and    eax,0xf
   140004bd0:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140004bd3:	83 7d f0 01          	cmp    DWORD PTR [rbp-0x10],0x1
   140004bd7:	75 36                	jne    140004c0f <__pformat_emit_xfloat+0x16f>
   140004bd9:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004bdd:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004be1:	72 1b                	jb     140004bfe <__pformat_emit_xfloat+0x15e>
   140004be3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004be7:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004bea:	25 00 08 00 00       	and    eax,0x800
   140004bef:	85 c0                	test   eax,eax
   140004bf1:	75 0b                	jne    140004bfe <__pformat_emit_xfloat+0x15e>
   140004bf3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004bf7:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004bfa:	85 c0                	test   eax,eax
   140004bfc:	7e 2d                	jle    140004c2b <__pformat_emit_xfloat+0x18b>
   140004bfe:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c02:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c06:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c0a:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004c0d:	eb 1c                	jmp    140004c2b <__pformat_emit_xfloat+0x18b>
   140004c0f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c13:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c16:	85 c0                	test   eax,eax
   140004c18:	7e 11                	jle    140004c2b <__pformat_emit_xfloat+0x18b>
   140004c1a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c1e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c21:	8d 50 ff             	lea    edx,[rax-0x1]
   140004c24:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c28:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140004c2b:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140004c2f:	75 15                	jne    140004c46 <__pformat_emit_xfloat+0x1a6>
   140004c31:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c35:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004c39:	72 0b                	jb     140004c46 <__pformat_emit_xfloat+0x1a6>
   140004c3b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c3f:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004c42:	85 c0                	test   eax,eax
   140004c44:	78 32                	js     140004c78 <__pformat_emit_xfloat+0x1d8>
   140004c46:	83 7d e4 09          	cmp    DWORD PTR [rbp-0x1c],0x9
   140004c4a:	76 16                	jbe    140004c62 <__pformat_emit_xfloat+0x1c2>
   140004c4c:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c4f:	8d 50 37             	lea    edx,[rax+0x37]
   140004c52:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c56:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004c59:	83 e0 20             	and    eax,0x20
   140004c5c:	09 d0                	or     eax,edx
   140004c5e:	89 c1                	mov    ecx,eax
   140004c60:	eb 08                	jmp    140004c6a <__pformat_emit_xfloat+0x1ca>
   140004c62:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140004c65:	83 c0 30             	add    eax,0x30
   140004c68:	89 c1                	mov    ecx,eax
   140004c6a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004c6e:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004c72:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004c76:	88 08                	mov    BYTE PTR [rax],cl
   140004c78:	48 8b 03             	mov    rax,QWORD PTR [rbx]
   140004c7b:	48 c1 e8 04          	shr    rax,0x4
   140004c7f:	48 89 03             	mov    QWORD PTR [rbx],rax
   140004c82:	83 6d f0 01          	sub    DWORD PTR [rbp-0x10],0x1
   140004c86:	83 7d f0 00          	cmp    DWORD PTR [rbp-0x10],0x0
   140004c8a:	0f 8f 3a ff ff ff    	jg     140004bca <__pformat_emit_xfloat+0x12a>
   140004c90:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004c94:	48 39 45 f8          	cmp    QWORD PTR [rbp-0x8],rax
   140004c98:	75 39                	jne    140004cd3 <__pformat_emit_xfloat+0x233>
   140004c9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004c9e:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ca1:	85 c0                	test   eax,eax
   140004ca3:	7f 10                	jg     140004cb5 <__pformat_emit_xfloat+0x215>
   140004ca5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ca9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004cac:	25 00 08 00 00       	and    eax,0x800
   140004cb1:	85 c0                	test   eax,eax
   140004cb3:	74 0f                	je     140004cc4 <__pformat_emit_xfloat+0x224>
   140004cb5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004cb9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004cbd:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004cc1:	c6 00 2e             	mov    BYTE PTR [rax],0x2e
   140004cc4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004cc8:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140004ccc:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   140004cd0:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140004cd3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cd7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004cda:	85 c0                	test   eax,eax
   140004cdc:	0f 8e e3 00 00 00    	jle    140004dc5 <__pformat_emit_xfloat+0x325>
   140004ce2:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004ce6:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140004cea:	48 29 c2             	sub    rdx,rax
   140004ced:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   140004cf0:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004cf4:	98                   	cwde
   140004cf5:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004cf8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004cfc:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004cff:	85 c0                	test   eax,eax
   140004d01:	7e 0a                	jle    140004d0d <__pformat_emit_xfloat+0x26d>
   140004d03:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d07:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004d0a:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004d0d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d11:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d14:	25 c0 01 00 00       	and    eax,0x1c0
   140004d19:	85 c0                	test   eax,eax
   140004d1b:	74 07                	je     140004d24 <__pformat_emit_xfloat+0x284>
   140004d1d:	b8 06 00 00 00       	mov    eax,0x6
   140004d22:	eb 05                	jmp    140004d29 <__pformat_emit_xfloat+0x289>
   140004d24:	b8 05 00 00 00       	mov    eax,0x5
   140004d29:	01 45 ec             	add    DWORD PTR [rbp-0x14],eax
   140004d2c:	eb 0f                	jmp    140004d3d <__pformat_emit_xfloat+0x29d>
   140004d2e:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
   140004d32:	0f b7 45 f6          	movzx  eax,WORD PTR [rbp-0xa]
   140004d36:	83 c0 01             	add    eax,0x1
   140004d39:	66 89 45 f6          	mov    WORD PTR [rbp-0xa],ax
   140004d3d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140004d40:	48 63 d0             	movsxd rdx,eax
   140004d43:	48 69 d2 67 66 66 66 	imul   rdx,rdx,0x66666667
   140004d4a:	48 c1 ea 20          	shr    rdx,0x20
   140004d4e:	89 d1                	mov    ecx,edx
   140004d50:	c1 f9 02             	sar    ecx,0x2
   140004d53:	99                   	cdq
   140004d54:	89 c8                	mov    eax,ecx
   140004d56:	29 d0                	sub    eax,edx
   140004d58:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140004d5b:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140004d5f:	75 cd                	jne    140004d2e <__pformat_emit_xfloat+0x28e>
   140004d61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d65:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d68:	39 45 ec             	cmp    DWORD PTR [rbp-0x14],eax
   140004d6b:	7d 4d                	jge    140004dba <__pformat_emit_xfloat+0x31a>
   140004d6d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d71:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004d74:	2b 45 ec             	sub    eax,DWORD PTR [rbp-0x14]
   140004d77:	89 c2                	mov    edx,eax
   140004d79:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d7d:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004d80:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d84:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004d87:	25 00 06 00 00       	and    eax,0x600
   140004d8c:	85 c0                	test   eax,eax
   140004d8e:	75 35                	jne    140004dc5 <__pformat_emit_xfloat+0x325>
   140004d90:	eb 11                	jmp    140004da3 <__pformat_emit_xfloat+0x303>
   140004d92:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004d96:	48 89 c2             	mov    rdx,rax
   140004d99:	b9 20 00 00 00       	mov    ecx,0x20
   140004d9e:	e8 bd e4 ff ff       	call   140003260 <__pformat_putc>
   140004da3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004da7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004daa:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004dad:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004db1:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004db4:	85 c0                	test   eax,eax
   140004db6:	7f da                	jg     140004d92 <__pformat_emit_xfloat+0x2f2>
   140004db8:	eb 0b                	jmp    140004dc5 <__pformat_emit_xfloat+0x325>
   140004dba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dbe:	c7 40 0c ff ff ff ff 	mov    DWORD PTR [rax+0xc],0xffffffff
   140004dc5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dc9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004dcc:	25 80 00 00 00       	and    eax,0x80
   140004dd1:	85 c0                	test   eax,eax
   140004dd3:	74 13                	je     140004de8 <__pformat_emit_xfloat+0x348>
   140004dd5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dd9:	48 89 c2             	mov    rdx,rax
   140004ddc:	b9 2d 00 00 00       	mov    ecx,0x2d
   140004de1:	e8 7a e4 ff ff       	call   140003260 <__pformat_putc>
   140004de6:	eb 42                	jmp    140004e2a <__pformat_emit_xfloat+0x38a>
   140004de8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dec:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004def:	25 00 01 00 00       	and    eax,0x100
   140004df4:	85 c0                	test   eax,eax
   140004df6:	74 13                	je     140004e0b <__pformat_emit_xfloat+0x36b>
   140004df8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004dfc:	48 89 c2             	mov    rdx,rax
   140004dff:	b9 2b 00 00 00       	mov    ecx,0x2b
   140004e04:	e8 57 e4 ff ff       	call   140003260 <__pformat_putc>
   140004e09:	eb 1f                	jmp    140004e2a <__pformat_emit_xfloat+0x38a>
   140004e0b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e0f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e12:	83 e0 40             	and    eax,0x40
   140004e15:	85 c0                	test   eax,eax
   140004e17:	74 11                	je     140004e2a <__pformat_emit_xfloat+0x38a>
   140004e19:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e1d:	48 89 c2             	mov    rdx,rax
   140004e20:	b9 20 00 00 00       	mov    ecx,0x20
   140004e25:	e8 36 e4 ff ff       	call   140003260 <__pformat_putc>
   140004e2a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e2e:	48 89 c2             	mov    rdx,rax
   140004e31:	b9 30 00 00 00       	mov    ecx,0x30
   140004e36:	e8 25 e4 ff ff       	call   140003260 <__pformat_putc>
   140004e3b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e3f:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e42:	83 e0 20             	and    eax,0x20
   140004e45:	83 c8 58             	or     eax,0x58
   140004e48:	89 c1                	mov    ecx,eax
   140004e4a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e4e:	48 89 c2             	mov    rdx,rax
   140004e51:	e8 0a e4 ff ff       	call   140003260 <__pformat_putc>
   140004e56:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e5a:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e5d:	85 c0                	test   eax,eax
   140004e5f:	7e 54                	jle    140004eb5 <__pformat_emit_xfloat+0x415>
   140004e61:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e65:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004e68:	25 00 02 00 00       	and    eax,0x200
   140004e6d:	85 c0                	test   eax,eax
   140004e6f:	74 44                	je     140004eb5 <__pformat_emit_xfloat+0x415>
   140004e71:	eb 11                	jmp    140004e84 <__pformat_emit_xfloat+0x3e4>
   140004e73:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e77:	48 89 c2             	mov    rdx,rax
   140004e7a:	b9 30 00 00 00       	mov    ecx,0x30
   140004e7f:	e8 dc e3 ff ff       	call   140003260 <__pformat_putc>
   140004e84:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004e88:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140004e8b:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004e8e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004e92:	89 4a 0c             	mov    DWORD PTR [rdx+0xc],ecx
   140004e95:	85 c0                	test   eax,eax
   140004e97:	7f da                	jg     140004e73 <__pformat_emit_xfloat+0x3d3>
   140004e99:	eb 1a                	jmp    140004eb5 <__pformat_emit_xfloat+0x415>
   140004e9b:	48 83 6d f8 01       	sub    QWORD PTR [rbp-0x8],0x1
   140004ea0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140004ea4:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140004ea7:	0f be c0             	movsx  eax,al
   140004eaa:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004eae:	89 c1                	mov    ecx,eax
   140004eb0:	e8 32 f2 ff ff       	call   1400040e7 <__pformat_emit_numeric_value>
   140004eb5:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004eb9:	48 3b 45 f8          	cmp    rax,QWORD PTR [rbp-0x8]
   140004ebd:	72 dc                	jb     140004e9b <__pformat_emit_xfloat+0x3fb>
   140004ebf:	eb 11                	jmp    140004ed2 <__pformat_emit_xfloat+0x432>
   140004ec1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ec5:	48 89 c2             	mov    rdx,rax
   140004ec8:	b9 30 00 00 00       	mov    ecx,0x30
   140004ecd:	e8 8e e3 ff ff       	call   140003260 <__pformat_putc>
   140004ed2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ed6:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   140004ed9:	8d 48 ff             	lea    ecx,[rax-0x1]
   140004edc:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004ee0:	89 4a 10             	mov    DWORD PTR [rdx+0x10],ecx
   140004ee3:	85 c0                	test   eax,eax
   140004ee5:	7f da                	jg     140004ec1 <__pformat_emit_xfloat+0x421>
   140004ee7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004eeb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004eee:	83 e0 20             	and    eax,0x20
   140004ef1:	83 c8 50             	or     eax,0x50
   140004ef4:	89 c1                	mov    ecx,eax
   140004ef6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004efa:	48 89 c2             	mov    rdx,rax
   140004efd:	e8 5e e3 ff ff       	call   140003260 <__pformat_putc>
   140004f02:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f06:	8b 50 0c             	mov    edx,DWORD PTR [rax+0xc]
   140004f09:	0f bf 45 f6          	movsx  eax,WORD PTR [rbp-0xa]
   140004f0d:	01 c2                	add    edx,eax
   140004f0f:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f13:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140004f16:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f1a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004f1d:	0d c0 01 00 00       	or     eax,0x1c0
   140004f22:	89 c2                	mov    edx,eax
   140004f24:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004f28:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140004f2b:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004f2f:	66 85 c0             	test   ax,ax
   140004f32:	79 09                	jns    140004f3d <__pformat_emit_xfloat+0x49d>
   140004f34:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140004f3b:	eb 05                	jmp    140004f42 <__pformat_emit_xfloat+0x4a2>
   140004f3d:	b8 00 00 00 00       	mov    eax,0x0
   140004f42:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140004f46:	0f b7 43 08          	movzx  eax,WORD PTR [rbx+0x8]
   140004f4a:	48 0f bf c0          	movsx  rax,ax
   140004f4e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140004f52:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140004f56:	48 8b 55 b8          	mov    rdx,QWORD PTR [rbp-0x48]
   140004f5a:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   140004f5e:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
   140004f62:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140004f66:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140004f6a:	48 89 c1             	mov    rcx,rax
   140004f6d:	e8 59 e7 ff ff       	call   1400036cb <__pformat_int>
   140004f72:	90                   	nop
   140004f73:	48 81 c4 88 00 00 00 	add    rsp,0x88
   140004f7a:	5b                   	pop    rbx
   140004f7b:	5d                   	pop    rbp
   140004f7c:	c3                   	ret

0000000140004f7d <__pformat_xldouble>:
   140004f7d:	55                   	push   rbp
   140004f7e:	53                   	push   rbx
   140004f7f:	48 83 ec 78          	sub    rsp,0x78
   140004f83:	48 8d 6c 24 70       	lea    rbp,[rsp+0x70]
   140004f88:	48 89 cb             	mov    rbx,rcx
   140004f8b:	db 2b                	fld    TBYTE PTR [rbx]
   140004f8d:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140004f90:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140004f94:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140004f9b:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   140004f9f:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fa2:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004fa5:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
   140004fa9:	48 89 c1             	mov    rcx,rax
   140004fac:	e8 e5 ed ff ff       	call   140003d96 <init_fpreg_ldouble>
   140004fb1:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140004fb4:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   140004fb7:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140004fbb:	48 89 c1             	mov    rcx,rax
   140004fbe:	e8 ed 3d 00 00       	call   140008db0 <__isnanl>
   140004fc3:	85 c0                	test   eax,eax
   140004fc5:	74 1d                	je     140004fe4 <__pformat_xldouble+0x67>
   140004fc7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140004fca:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140004fce:	48 8d 15 91 63 00 00 	lea    rdx,[rip+0x6391]        # 14000b366 <.rdata+0x16>
   140004fd5:	49 89 c8             	mov    r8,rcx
   140004fd8:	89 c1                	mov    ecx,eax
   140004fda:	e8 75 f1 ff ff       	call   140004154 <__pformat_emit_inf_or_nan>
   140004fdf:	e9 aa 00 00 00       	jmp    14000508e <__pformat_xldouble+0x111>
   140004fe4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140004fe8:	98                   	cwde
   140004fe9:	25 00 80 00 00       	and    eax,0x8000
   140004fee:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140004ff1:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140004ff5:	74 12                	je     140005009 <__pformat_xldouble+0x8c>
   140004ff7:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140004ffb:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140004ffe:	0c 80                	or     al,0x80
   140005000:	89 c2                	mov    edx,eax
   140005002:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005006:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005009:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   14000500c:	db 7d c0             	fstp   TBYTE PTR [rbp-0x40]
   14000500f:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   140005013:	48 89 c1             	mov    rcx,rax
   140005016:	e8 a5 3c 00 00       	call   140008cc0 <__fpclassifyl>
   14000501b:	3d 00 05 00 00       	cmp    eax,0x500
   140005020:	75 1a                	jne    14000503c <__pformat_xldouble+0xbf>
   140005022:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005025:	48 8b 4d 28          	mov    rcx,QWORD PTR [rbp+0x28]
   140005029:	48 8d 15 3a 63 00 00 	lea    rdx,[rip+0x633a]        # 14000b36a <.rdata+0x1a>
   140005030:	49 89 c8             	mov    r8,rcx
   140005033:	89 c1                	mov    ecx,eax
   140005035:	e8 1a f1 ff ff       	call   140004154 <__pformat_emit_inf_or_nan>
   14000503a:	eb 52                	jmp    14000508e <__pformat_xldouble+0x111>
   14000503c:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005040:	66 25 ff 7f          	and    ax,0x7fff
   140005044:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005048:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000504c:	66 85 c0             	test   ax,ax
   14000504f:	75 11                	jne    140005062 <__pformat_xldouble+0xe5>
   140005051:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005055:	48 85 c0             	test   rax,rax
   140005058:	74 14                	je     14000506e <__pformat_xldouble+0xf1>
   14000505a:	66 c7 45 e8 02 c0    	mov    WORD PTR [rbp-0x18],0xc002
   140005060:	eb 0c                	jmp    14000506e <__pformat_xldouble+0xf1>
   140005062:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005066:	66 2d ff 3f          	sub    ax,0x3fff
   14000506a:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000506e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005072:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140005076:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000507a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
   14000507e:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   140005082:	48 8d 45 b0          	lea    rax,[rbp-0x50]
   140005086:	48 89 c1             	mov    rcx,rax
   140005089:	e8 12 fa ff ff       	call   140004aa0 <__pformat_emit_xfloat>
   14000508e:	90                   	nop
   14000508f:	48 83 c4 78          	add    rsp,0x78
   140005093:	5b                   	pop    rbx
   140005094:	5d                   	pop    rbp
   140005095:	c3                   	ret

0000000140005096 <__pformat_xdouble>:
   140005096:	55                   	push   rbp
   140005097:	48 89 e5             	mov    rbp,rsp
   14000509a:	48 83 ec 60          	sub    rsp,0x60
   14000509e:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   1400050a3:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400050a7:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400050ae:	dd 45 10             	fld    QWORD PTR [rbp+0x10]
   1400050b1:	48 8d 45 e0          	lea    rax,[rbp-0x20]
   1400050b5:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   1400050b8:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
   1400050bc:	48 89 c1             	mov    rcx,rax
   1400050bf:	e8 d2 ec ff ff       	call   140003d96 <init_fpreg_ldouble>
   1400050c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400050c8:	66 48 0f 6e c0       	movq   xmm0,rax
   1400050cd:	e8 7e 3c 00 00       	call   140008d50 <__isnan>
   1400050d2:	85 c0                	test   eax,eax
   1400050d4:	74 1d                	je     1400050f3 <__pformat_xdouble+0x5d>
   1400050d6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400050d9:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   1400050dd:	48 8d 15 82 62 00 00 	lea    rdx,[rip+0x6282]        # 14000b366 <.rdata+0x16>
   1400050e4:	49 89 c8             	mov    r8,rcx
   1400050e7:	89 c1                	mov    ecx,eax
   1400050e9:	e8 66 f0 ff ff       	call   140004154 <__pformat_emit_inf_or_nan>
   1400050ee:	e9 f9 00 00 00       	jmp    1400051ec <__pformat_xdouble+0x156>
   1400050f3:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400050f7:	98                   	cwde
   1400050f8:	25 00 80 00 00       	and    eax,0x8000
   1400050fd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005100:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005104:	74 12                	je     140005118 <__pformat_xdouble+0x82>
   140005106:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000510a:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000510d:	0c 80                	or     al,0x80
   14000510f:	89 c2                	mov    edx,eax
   140005111:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005115:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005118:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000511c:	66 48 0f 6e c0       	movq   xmm0,rax
   140005121:	e8 1a 3b 00 00       	call   140008c40 <__fpclassify>
   140005126:	3d 00 05 00 00       	cmp    eax,0x500
   14000512b:	75 1d                	jne    14000514a <__pformat_xdouble+0xb4>
   14000512d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005130:	48 8b 4d 18          	mov    rcx,QWORD PTR [rbp+0x18]
   140005134:	48 8d 15 2f 62 00 00 	lea    rdx,[rip+0x622f]        # 14000b36a <.rdata+0x1a>
   14000513b:	49 89 c8             	mov    r8,rcx
   14000513e:	89 c1                	mov    ecx,eax
   140005140:	e8 0f f0 ff ff       	call   140004154 <__pformat_emit_inf_or_nan>
   140005145:	e9 a2 00 00 00       	jmp    1400051ec <__pformat_xdouble+0x156>
   14000514a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000514e:	66 25 ff 7f          	and    ax,0x7fff
   140005152:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   140005156:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000515a:	66 85 c0             	test   ax,ax
   14000515d:	74 3b                	je     14000519a <__pformat_xdouble+0x104>
   14000515f:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140005163:	66 3d 00 3c          	cmp    ax,0x3c00
   140005167:	7f 31                	jg     14000519a <__pformat_xdouble+0x104>
   140005169:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000516d:	98                   	cwde
   14000516e:	ba 01 3c 00 00       	mov    edx,0x3c01
   140005173:	29 c2                	sub    edx,eax
   140005175:	89 55 f8             	mov    DWORD PTR [rbp-0x8],edx
   140005178:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   14000517c:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000517f:	89 c1                	mov    ecx,eax
   140005181:	48 d3 ea             	shr    rdx,cl
   140005184:	48 89 d0             	mov    rax,rdx
   140005187:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000518b:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000518f:	89 c2                	mov    edx,eax
   140005191:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005194:	01 d0                	add    eax,edx
   140005196:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   14000519a:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   14000519e:	66 85 c0             	test   ax,ax
   1400051a1:	75 11                	jne    1400051b4 <__pformat_xdouble+0x11e>
   1400051a3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051a7:	48 85 c0             	test   rax,rax
   1400051aa:	74 14                	je     1400051c0 <__pformat_xdouble+0x12a>
   1400051ac:	66 c7 45 e8 05 fc    	mov    WORD PTR [rbp-0x18],0xfc05
   1400051b2:	eb 0c                	jmp    1400051c0 <__pformat_xdouble+0x12a>
   1400051b4:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   1400051b8:	66 2d fc 3f          	sub    ax,0x3ffc
   1400051bc:	66 89 45 e8          	mov    WORD PTR [rbp-0x18],ax
   1400051c0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051c4:	48 c1 e8 03          	shr    rax,0x3
   1400051c8:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400051cc:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400051d0:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400051d4:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   1400051d8:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
   1400051dc:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400051e0:	48 8d 45 c0          	lea    rax,[rbp-0x40]
   1400051e4:	48 89 c1             	mov    rcx,rax
   1400051e7:	e8 b4 f8 ff ff       	call   140004aa0 <__pformat_emit_xfloat>
   1400051ec:	90                   	nop
   1400051ed:	48 83 c4 60          	add    rsp,0x60
   1400051f1:	5d                   	pop    rbp
   1400051f2:	c3                   	ret

00000001400051f3 <__mingw_pformat>:
   1400051f3:	55                   	push   rbp
   1400051f4:	48 89 e5             	mov    rbp,rsp
   1400051f7:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
   1400051fe:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005201:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005205:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005209:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   14000520d:	e8 a6 44 00 00       	call   1400096b8 <_errno>
   140005212:	8b 00                	mov    eax,DWORD PTR [rax]
   140005214:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140005217:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000521b:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
   14000521f:	81 65 10 00 60 00 00 	and    DWORD PTR [rbp+0x10],0x6000
   140005226:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140005229:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000522c:	c7 45 ac ff ff ff ff 	mov    DWORD PTR [rbp-0x54],0xffffffff
   140005233:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   14000523a:	c7 45 b4 fd ff ff ff 	mov    DWORD PTR [rbp-0x4c],0xfffffffd
   140005241:	66 c7 45 b8 00 00    	mov    WORD PTR [rbp-0x48],0x0
   140005247:	c7 45 bc 00 00 00 00 	mov    DWORD PTR [rbp-0x44],0x0
   14000524e:	66 c7 45 c0 00 00    	mov    WORD PTR [rbp-0x40],0x0
   140005254:	c7 45 c4 00 00 00 00 	mov    DWORD PTR [rbp-0x3c],0x0
   14000525b:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   14000525e:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
   140005261:	c7 45 cc ff ff ff ff 	mov    DWORD PTR [rbp-0x34],0xffffffff
   140005268:	e9 27 0c 00 00       	jmp    140005e94 <__mingw_pformat+0xca1>
   14000526d:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   140005271:	0f 85 0f 0c 00 00    	jne    140005e86 <__mingw_pformat+0xc93>
   140005277:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   14000527e:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005285:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005289:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000528d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005291:	48 83 c0 0c          	add    rax,0xc
   140005295:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005299:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   14000529c:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   14000529f:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400052a6:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400052a9:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   1400052ac:	e9 c4 0b 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   1400052b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400052b5:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400052b9:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   1400052bd:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400052c0:	0f be c0             	movsx  eax,al
   1400052c3:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400052c6:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400052ca:	0f 84 94 09 00 00    	je     140005c64 <__mingw_pformat+0xa71>
   1400052d0:	83 7d e8 7a          	cmp    DWORD PTR [rbp-0x18],0x7a
   1400052d4:	0f 8f 02 0b 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400052da:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052de:	0f 84 eb 03 00 00    	je     1400056cf <__mingw_pformat+0x4dc>
   1400052e4:	83 7d e8 78          	cmp    DWORD PTR [rbp-0x18],0x78
   1400052e8:	0f 8f ee 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400052ee:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052f2:	0f 84 31 09 00 00    	je     140005c29 <__mingw_pformat+0xa36>
   1400052f8:	83 7d e8 77          	cmp    DWORD PTR [rbp-0x18],0x77
   1400052fc:	0f 8f da 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005302:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005306:	0f 84 c3 03 00 00    	je     1400056cf <__mingw_pformat+0x4dc>
   14000530c:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   140005310:	0f 8f c6 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005316:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   14000531a:	0f 84 31 09 00 00    	je     140005c51 <__mingw_pformat+0xa5e>
   140005320:	83 7d e8 74          	cmp    DWORD PTR [rbp-0x18],0x74
   140005324:	0f 8f b2 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000532a:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   14000532e:	0f 84 31 03 00 00    	je     140005665 <__mingw_pformat+0x472>
   140005334:	83 7d e8 73          	cmp    DWORD PTR [rbp-0x18],0x73
   140005338:	0f 8f 9e 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000533e:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   140005342:	0f 84 28 05 00 00    	je     140005870 <__mingw_pformat+0x67d>
   140005348:	83 7d e8 70          	cmp    DWORD PTR [rbp-0x18],0x70
   14000534c:	0f 8f 8a 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005352:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005356:	0f 84 73 03 00 00    	je     1400056cf <__mingw_pformat+0x4dc>
   14000535c:	83 7d e8 6f          	cmp    DWORD PTR [rbp-0x18],0x6f
   140005360:	0f 8f 76 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005366:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   14000536a:	0f 84 4d 07 00 00    	je     140005abd <__mingw_pformat+0x8ca>
   140005370:	83 7d e8 6e          	cmp    DWORD PTR [rbp-0x18],0x6e
   140005374:	0f 8f 62 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000537a:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   14000537e:	0f 84 2d 03 00 00    	je     1400056b1 <__mingw_pformat+0x4be>
   140005384:	83 7d e8 6d          	cmp    DWORD PTR [rbp-0x18],0x6d
   140005388:	0f 8f 4e 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000538e:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   140005392:	0f 84 65 08 00 00    	je     140005bfd <__mingw_pformat+0xa0a>
   140005398:	83 7d e8 6c          	cmp    DWORD PTR [rbp-0x18],0x6c
   14000539c:	0f 8f 3a 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400053a2:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400053a6:	0f 84 db 07 00 00    	je     140005b87 <__mingw_pformat+0x994>
   1400053ac:	83 7d e8 6a          	cmp    DWORD PTR [rbp-0x18],0x6a
   1400053b0:	0f 8f 26 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400053b6:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400053ba:	0f 84 ee 03 00 00    	je     1400057ae <__mingw_pformat+0x5bb>
   1400053c0:	83 7d e8 69          	cmp    DWORD PTR [rbp-0x18],0x69
   1400053c4:	0f 8f 12 0a 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400053ca:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400053ce:	0f 84 87 07 00 00    	je     140005b5b <__mingw_pformat+0x968>
   1400053d4:	83 7d e8 68          	cmp    DWORD PTR [rbp-0x18],0x68
   1400053d8:	0f 8f fe 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400053de:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053e2:	0f 84 f3 05 00 00    	je     1400059db <__mingw_pformat+0x7e8>
   1400053e8:	83 7d e8 67          	cmp    DWORD PTR [rbp-0x18],0x67
   1400053ec:	0f 8f ea 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400053f2:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   1400053f6:	0f 84 61 05 00 00    	je     14000595d <__mingw_pformat+0x76a>
   1400053fc:	83 7d e8 66          	cmp    DWORD PTR [rbp-0x18],0x66
   140005400:	0f 8f d6 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005406:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   14000540a:	0f 84 cf 04 00 00    	je     1400058df <__mingw_pformat+0x6ec>
   140005410:	83 7d e8 65          	cmp    DWORD PTR [rbp-0x18],0x65
   140005414:	0f 8f c2 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000541a:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   14000541e:	0f 84 8a 03 00 00    	je     1400057ae <__mingw_pformat+0x5bb>
   140005424:	83 7d e8 64          	cmp    DWORD PTR [rbp-0x18],0x64
   140005428:	0f 8f ae 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000542e:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   140005432:	0f 84 b5 01 00 00    	je     1400055ed <__mingw_pformat+0x3fa>
   140005438:	83 7d e8 63          	cmp    DWORD PTR [rbp-0x18],0x63
   14000543c:	0f 8f 9a 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005442:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005446:	0f 84 83 02 00 00    	je     1400056cf <__mingw_pformat+0x4dc>
   14000544c:	83 7d e8 62          	cmp    DWORD PTR [rbp-0x18],0x62
   140005450:	0f 8f 86 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005456:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   14000545a:	0f 84 f9 05 00 00    	je     140005a59 <__mingw_pformat+0x866>
   140005460:	83 7d e8 61          	cmp    DWORD PTR [rbp-0x18],0x61
   140005464:	0f 8f 72 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000546a:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   14000546e:	0f 84 5b 02 00 00    	je     1400056cf <__mingw_pformat+0x4dc>
   140005474:	83 7d e8 58          	cmp    DWORD PTR [rbp-0x18],0x58
   140005478:	0f 8f 5e 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000547e:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   140005482:	0f 84 d6 01 00 00    	je     14000565e <__mingw_pformat+0x46b>
   140005488:	83 7d e8 53          	cmp    DWORD PTR [rbp-0x18],0x53
   14000548c:	0f 8f 4a 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005492:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   140005496:	0f 84 a0 07 00 00    	je     140005c3c <__mingw_pformat+0xa49>
   14000549c:	83 7d e8 4c          	cmp    DWORD PTR [rbp-0x18],0x4c
   1400054a0:	0f 8f 36 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400054a6:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400054aa:	0f 84 ea 06 00 00    	je     140005b9a <__mingw_pformat+0x9a7>
   1400054b0:	83 7d e8 49          	cmp    DWORD PTR [rbp-0x18],0x49
   1400054b4:	0f 8f 22 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400054ba:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400054be:	0f 84 20 05 00 00    	je     1400059e4 <__mingw_pformat+0x7f1>
   1400054c4:	83 7d e8 47          	cmp    DWORD PTR [rbp-0x18],0x47
   1400054c8:	0f 8f 0e 09 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400054ce:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054d2:	0f 84 8e 04 00 00    	je     140005966 <__mingw_pformat+0x773>
   1400054d8:	83 7d e8 46          	cmp    DWORD PTR [rbp-0x18],0x46
   1400054dc:	0f 8f fa 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400054e2:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054e6:	0f 84 fc 03 00 00    	je     1400058e8 <__mingw_pformat+0x6f5>
   1400054ec:	83 7d e8 45          	cmp    DWORD PTR [rbp-0x18],0x45
   1400054f0:	0f 8f e6 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400054f6:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   1400054fa:	0f 84 e6 00 00 00    	je     1400055e6 <__mingw_pformat+0x3f3>
   140005500:	83 7d e8 43          	cmp    DWORD PTR [rbp-0x18],0x43
   140005504:	0f 8f d2 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000550a:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   14000550e:	0f 84 bb 01 00 00    	je     1400056cf <__mingw_pformat+0x4dc>
   140005514:	83 7d e8 42          	cmp    DWORD PTR [rbp-0x18],0x42
   140005518:	0f 8f be 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000551e:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   140005522:	0f 84 3a 05 00 00    	je     140005a62 <__mingw_pformat+0x86f>
   140005528:	83 7d e8 41          	cmp    DWORD PTR [rbp-0x18],0x41
   14000552c:	0f 8f aa 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005532:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005536:	0f 84 8c 08 00 00    	je     140005dc8 <__mingw_pformat+0xbd5>
   14000553c:	83 7d e8 30          	cmp    DWORD PTR [rbp-0x18],0x30
   140005540:	0f 8f 96 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005546:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   14000554a:	0f 84 27 07 00 00    	je     140005c77 <__mingw_pformat+0xa84>
   140005550:	83 7d e8 2e          	cmp    DWORD PTR [rbp-0x18],0x2e
   140005554:	0f 8f 82 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000555a:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   14000555e:	0f 84 db 07 00 00    	je     140005d3f <__mingw_pformat+0xb4c>
   140005564:	83 7d e8 2d          	cmp    DWORD PTR [rbp-0x18],0x2d
   140005568:	0f 8f 6e 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   14000556e:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   140005572:	0f 84 af 07 00 00    	je     140005d27 <__mingw_pformat+0xb34>
   140005578:	83 7d e8 2b          	cmp    DWORD PTR [rbp-0x18],0x2b
   14000557c:	0f 8f 5a 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005582:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005586:	0f 84 1c 07 00 00    	je     140005ca8 <__mingw_pformat+0xab5>
   14000558c:	83 7d e8 2a          	cmp    DWORD PTR [rbp-0x18],0x2a
   140005590:	0f 8f 46 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   140005596:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   14000559a:	0f 84 b7 07 00 00    	je     140005d57 <__mingw_pformat+0xb64>
   1400055a0:	83 7d e8 27          	cmp    DWORD PTR [rbp-0x18],0x27
   1400055a4:	0f 8f 32 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400055aa:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400055ae:	74 23                	je     1400055d3 <__mingw_pformat+0x3e0>
   1400055b0:	83 7d e8 25          	cmp    DWORD PTR [rbp-0x18],0x25
   1400055b4:	0f 8f 22 08 00 00    	jg     140005ddc <__mingw_pformat+0xbe9>
   1400055ba:	83 7d e8 20          	cmp    DWORD PTR [rbp-0x18],0x20
   1400055be:	0f 84 ec 07 00 00    	je     140005db0 <__mingw_pformat+0xbbd>
   1400055c4:	83 7d e8 23          	cmp    DWORD PTR [rbp-0x18],0x23
   1400055c8:	0f 84 41 07 00 00    	je     140005d0f <__mingw_pformat+0xb1c>
   1400055ce:	e9 09 08 00 00       	jmp    140005ddc <__mingw_pformat+0xbe9>
   1400055d3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400055d7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400055da:	89 c1                	mov    ecx,eax
   1400055dc:	e8 7f dc ff ff       	call   140003260 <__pformat_putc>
   1400055e1:	e9 82 fc ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   1400055e6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   1400055ed:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   1400055f4:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400055f8:	74 06                	je     140005600 <__mingw_pformat+0x40d>
   1400055fa:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400055fe:	75 30                	jne    140005630 <__mingw_pformat+0x43d>
   140005600:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005604:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005608:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000560c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000560e:	66 89 45 8e          	mov    WORD PTR [rbp-0x72],ax
   140005612:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005616:	48 8d 45 8e          	lea    rax,[rbp-0x72]
   14000561a:	49 89 d0             	mov    r8,rdx
   14000561d:	ba 01 00 00 00       	mov    edx,0x1
   140005622:	48 89 c1             	mov    rcx,rax
   140005625:	e8 3f de ff ff       	call   140003469 <__pformat_wputchars>
   14000562a:	90                   	nop
   14000562b:	e9 38 fc ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005630:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005634:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005638:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000563c:	8b 00                	mov    eax,DWORD PTR [rax]
   14000563e:	88 45 90             	mov    BYTE PTR [rbp-0x70],al
   140005641:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005645:	48 8d 45 90          	lea    rax,[rbp-0x70]
   140005649:	49 89 d0             	mov    r8,rdx
   14000564c:	ba 01 00 00 00       	mov    edx,0x1
   140005651:	48 89 c1             	mov    rcx,rax
   140005654:	e8 8b dc ff ff       	call   1400032e4 <__pformat_putchars>
   140005659:	e9 0a fc ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   14000565e:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005665:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005669:	74 06                	je     140005671 <__mingw_pformat+0x47e>
   14000566b:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   14000566f:	75 20                	jne    140005691 <__mingw_pformat+0x49e>
   140005671:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005675:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005679:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000567d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005680:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005684:	48 89 c1             	mov    rcx,rax
   140005687:	e8 29 df ff ff       	call   1400035b5 <__pformat_wcputs>
   14000568c:	e9 d7 fb ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005691:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005695:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005699:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000569d:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056a0:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400056a4:	48 89 c1             	mov    rcx,rax
   1400056a7:	e8 37 dd ff ff       	call   1400033e3 <__pformat_puts>
   1400056ac:	e9 b7 fb ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   1400056b1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400056b4:	89 c1                	mov    ecx,eax
   1400056b6:	e8 95 40 00 00       	call   140009750 <strerror>
   1400056bb:	48 89 c1             	mov    rcx,rax
   1400056be:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   1400056c2:	48 89 c2             	mov    rdx,rax
   1400056c5:	e8 19 dd ff ff       	call   1400033e3 <__pformat_puts>
   1400056ca:	e9 99 fb ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   1400056cf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400056d2:	80 e4 fe             	and    ah,0xfe
   1400056d5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400056d8:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400056dc:	75 15                	jne    1400056f3 <__mingw_pformat+0x500>
   1400056de:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056e2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400056e6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400056ea:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400056ed:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400056f1:	eb 54                	jmp    140005747 <__mingw_pformat+0x554>
   1400056f3:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400056f7:	75 16                	jne    14000570f <__mingw_pformat+0x51c>
   1400056f9:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400056fd:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005701:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005705:	8b 00                	mov    eax,DWORD PTR [rax]
   140005707:	89 c0                	mov    eax,eax
   140005709:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   14000570d:	eb 38                	jmp    140005747 <__mingw_pformat+0x554>
   14000570f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005713:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005717:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000571b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000571d:	89 c0                	mov    eax,eax
   14000571f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005723:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005727:	75 0d                	jne    140005736 <__mingw_pformat+0x543>
   140005729:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000572d:	0f b7 c0             	movzx  eax,ax
   140005730:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005734:	eb 11                	jmp    140005747 <__mingw_pformat+0x554>
   140005736:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   14000573a:	75 0b                	jne    140005747 <__mingw_pformat+0x554>
   14000573c:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   140005740:	0f b6 c0             	movzx  eax,al
   140005743:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005747:	83 7d e8 75          	cmp    DWORD PTR [rbp-0x18],0x75
   14000574b:	75 2e                	jne    14000577b <__mingw_pformat+0x588>
   14000574d:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005751:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005755:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000575c:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005763:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005767:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   14000576e:	48 89 c1             	mov    rcx,rax
   140005771:	e8 55 df ff ff       	call   1400036cb <__pformat_int>
   140005776:	e9 ed fa ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   14000577b:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000577f:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140005783:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   14000578a:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005791:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
   140005795:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
   14000579c:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   14000579f:	49 89 c8             	mov    r8,rcx
   1400057a2:	89 c1                	mov    ecx,eax
   1400057a4:	e8 a5 e2 ff ff       	call   140003a4e <__pformat_xint>
   1400057a9:	e9 ba fa ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   1400057ae:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400057b1:	0c 80                	or     al,0x80
   1400057b3:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400057b6:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   1400057ba:	75 15                	jne    1400057d1 <__mingw_pformat+0x5de>
   1400057bc:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057c0:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057c4:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057c8:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400057cb:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057cf:	eb 56                	jmp    140005827 <__mingw_pformat+0x634>
   1400057d1:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   1400057d5:	75 16                	jne    1400057ed <__mingw_pformat+0x5fa>
   1400057d7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057db:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057df:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057e3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057e5:	48 98                	cdqe
   1400057e7:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400057eb:	eb 3a                	jmp    140005827 <__mingw_pformat+0x634>
   1400057ed:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400057f1:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400057f5:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400057f9:	8b 00                	mov    eax,DWORD PTR [rax]
   1400057fb:	48 98                	cdqe
   1400057fd:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005801:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005805:	75 0e                	jne    140005815 <__mingw_pformat+0x622>
   140005807:	0f b7 45 90          	movzx  eax,WORD PTR [rbp-0x70]
   14000580b:	48 0f bf c0          	movsx  rax,ax
   14000580f:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005813:	eb 12                	jmp    140005827 <__mingw_pformat+0x634>
   140005815:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005819:	75 0c                	jne    140005827 <__mingw_pformat+0x634>
   14000581b:	0f b6 45 90          	movzx  eax,BYTE PTR [rbp-0x70]
   14000581f:	48 0f be c0          	movsx  rax,al
   140005823:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   140005827:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   14000582b:	48 85 c0             	test   rax,rax
   14000582e:	79 09                	jns    140005839 <__mingw_pformat+0x646>
   140005830:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140005837:	eb 05                	jmp    14000583e <__mingw_pformat+0x64b>
   140005839:	b8 00 00 00 00       	mov    eax,0x0
   14000583e:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140005842:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   140005846:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   14000584a:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   140005851:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   140005858:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000585c:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   140005863:	48 89 c1             	mov    rcx,rax
   140005866:	e8 60 de ff ff       	call   1400036cb <__pformat_int>
   14000586b:	e9 f8 f9 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005870:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005874:	75 18                	jne    14000588e <__mingw_pformat+0x69b>
   140005876:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005879:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   14000587c:	75 10                	jne    14000588e <__mingw_pformat+0x69b>
   14000587e:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005881:	80 cc 02             	or     ah,0x2
   140005884:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005887:	c7 45 b0 10 00 00 00 	mov    DWORD PTR [rbp-0x50],0x10
   14000588e:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005892:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005896:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000589a:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000589d:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
   1400058a1:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
   1400058a8:	00 
   1400058a9:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
   1400058ad:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   1400058b1:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
   1400058b8:	48 89 95 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdx
   1400058bf:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400058c3:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
   1400058ca:	49 89 d0             	mov    r8,rdx
   1400058cd:	48 89 c2             	mov    rdx,rax
   1400058d0:	b9 78 00 00 00       	mov    ecx,0x78
   1400058d5:	e8 74 e1 ff ff       	call   140003a4e <__pformat_xint>
   1400058da:	e9 89 f9 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   1400058df:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058e2:	83 c8 20             	or     eax,0x20
   1400058e5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400058e8:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400058eb:	83 e0 04             	and    eax,0x4
   1400058ee:	85 c0                	test   eax,eax
   1400058f0:	74 2f                	je     140005921 <__mingw_pformat+0x72e>
   1400058f2:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400058f6:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400058fa:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400058fe:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005901:	db 28                	fld    TBYTE PTR [rax]
   140005903:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005909:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000590d:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005914:	48 89 c1             	mov    rcx,rax
   140005917:	e8 1d ef ff ff       	call   140004839 <__pformat_efloat>
   14000591c:	e9 47 f9 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005921:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005925:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005929:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000592d:	f2 0f 10 08          	movsd  xmm1,QWORD PTR [rax]
   140005931:	f2 0f 11 8d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm1
   140005938:	ff 
   140005939:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   14000593f:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005945:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005949:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005950:	48 89 c1             	mov    rcx,rax
   140005953:	e8 e1 ee ff ff       	call   140004839 <__pformat_efloat>
   140005958:	e9 0b f9 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   14000595d:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005960:	83 c8 20             	or     eax,0x20
   140005963:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005966:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005969:	83 e0 04             	and    eax,0x4
   14000596c:	85 c0                	test   eax,eax
   14000596e:	74 2f                	je     14000599f <__mingw_pformat+0x7ac>
   140005970:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005974:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005978:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   14000597c:	48 8b 00             	mov    rax,QWORD PTR [rax]
   14000597f:	db 28                	fld    TBYTE PTR [rax]
   140005981:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005987:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   14000598b:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005992:	48 89 c1             	mov    rcx,rax
   140005995:	e8 cf ed ff ff       	call   140004769 <__pformat_float>
   14000599a:	e9 c9 f8 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   14000599f:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059a3:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059a7:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059ab:	f2 0f 10 10          	movsd  xmm2,QWORD PTR [rax]
   1400059af:	f2 0f 11 95 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm2
   1400059b6:	ff 
   1400059b7:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   1400059bd:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   1400059c3:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   1400059c7:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   1400059ce:	48 89 c1             	mov    rcx,rax
   1400059d1:	e8 93 ed ff ff       	call   140004769 <__pformat_float>
   1400059d6:	e9 8d f8 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   1400059db:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059de:	83 c8 20             	or     eax,0x20
   1400059e1:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   1400059e4:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   1400059e7:	83 e0 04             	and    eax,0x4
   1400059ea:	85 c0                	test   eax,eax
   1400059ec:	74 2f                	je     140005a1d <__mingw_pformat+0x82a>
   1400059ee:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   1400059f2:	48 8d 50 08          	lea    rdx,[rax+0x8]
   1400059f6:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   1400059fa:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400059fd:	db 28                	fld    TBYTE PTR [rax]
   1400059ff:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a05:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a09:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a10:	48 89 c1             	mov    rcx,rax
   140005a13:	e8 cc ee ff ff       	call   1400048e4 <__pformat_gfloat>
   140005a18:	e9 4b f8 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005a1d:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a21:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a25:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a29:	f2 0f 10 18          	movsd  xmm3,QWORD PTR [rax]
   140005a2d:	f2 0f 11 9d 58 ff ff 	movsd  QWORD PTR [rbp-0xa8],xmm3
   140005a34:	ff 
   140005a35:	dd 85 58 ff ff ff    	fld    QWORD PTR [rbp-0xa8]
   140005a3b:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a41:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a45:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a4c:	48 89 c1             	mov    rcx,rax
   140005a4f:	e8 90 ee ff ff       	call   1400048e4 <__pformat_gfloat>
   140005a54:	e9 0f f8 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005a59:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a5c:	83 c8 20             	or     eax,0x20
   140005a5f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005a62:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005a65:	83 e0 04             	and    eax,0x4
   140005a68:	85 c0                	test   eax,eax
   140005a6a:	74 2f                	je     140005a9b <__mingw_pformat+0x8a8>
   140005a6c:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a70:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005a74:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005a78:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005a7b:	db 28                	fld    TBYTE PTR [rax]
   140005a7d:	db bd 60 ff ff ff    	fstp   TBYTE PTR [rbp-0xa0]
   140005a83:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005a87:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
   140005a8e:	48 89 c1             	mov    rcx,rax
   140005a91:	e8 e7 f4 ff ff       	call   140004f7d <__pformat_xldouble>
   140005a96:	e9 cd f7 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005a9b:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005a9f:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aa3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005aa7:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005aaa:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005aae:	66 48 0f 6e c0       	movq   xmm0,rax
   140005ab3:	e8 de f5 ff ff       	call   140005096 <__pformat_xdouble>
   140005ab8:	e9 ab f7 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005abd:	83 7d f8 05          	cmp    DWORD PTR [rbp-0x8],0x5
   140005ac1:	75 1b                	jne    140005ade <__mingw_pformat+0x8eb>
   140005ac3:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ac6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005aca:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005ace:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005ad2:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005ad5:	89 ca                	mov    edx,ecx
   140005ad7:	88 10                	mov    BYTE PTR [rax],dl
   140005ad9:	e9 8a f7 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005ade:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
   140005ae2:	75 1c                	jne    140005b00 <__mingw_pformat+0x90d>
   140005ae4:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005ae7:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005aeb:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005aef:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005af3:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005af6:	89 ca                	mov    edx,ecx
   140005af8:	66 89 10             	mov    WORD PTR [rax],dx
   140005afb:	e9 68 f7 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005b00:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140005b04:	75 19                	jne    140005b1f <__mingw_pformat+0x92c>
   140005b06:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b0a:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b0e:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b12:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b15:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005b18:	89 10                	mov    DWORD PTR [rax],edx
   140005b1a:	e9 49 f7 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005b1f:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
   140005b23:	75 1d                	jne    140005b42 <__mingw_pformat+0x94f>
   140005b25:	8b 4d c4             	mov    ecx,DWORD PTR [rbp-0x3c]
   140005b28:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b2c:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b30:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b34:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b37:	48 63 d1             	movsxd rdx,ecx
   140005b3a:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005b3d:	e9 26 f7 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005b42:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005b46:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005b4a:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005b4e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140005b51:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   140005b54:	89 10                	mov    DWORD PTR [rax],edx
   140005b56:	e9 0d f7 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005b5b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b5f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005b62:	3c 68                	cmp    al,0x68
   140005b64:	75 0e                	jne    140005b74 <__mingw_pformat+0x981>
   140005b66:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005b6b:	c7 45 f8 05 00 00 00 	mov    DWORD PTR [rbp-0x8],0x5
   140005b72:	eb 07                	jmp    140005b7b <__mingw_pformat+0x988>
   140005b74:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   140005b7b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b82:	e9 ee 02 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005b87:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005b8e:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005b95:	e9 db 02 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005b9a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005b9e:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ba1:	3c 36                	cmp    al,0x36
   140005ba3:	75 1d                	jne    140005bc2 <__mingw_pformat+0x9cf>
   140005ba5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005ba9:	48 83 c0 01          	add    rax,0x1
   140005bad:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bb0:	3c 34                	cmp    al,0x34
   140005bb2:	75 0e                	jne    140005bc2 <__mingw_pformat+0x9cf>
   140005bb4:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bbb:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005bc0:	eb 2f                	jmp    140005bf1 <__mingw_pformat+0x9fe>
   140005bc2:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bc6:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bc9:	3c 33                	cmp    al,0x33
   140005bcb:	75 1d                	jne    140005bea <__mingw_pformat+0x9f7>
   140005bcd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005bd1:	48 83 c0 01          	add    rax,0x1
   140005bd5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005bd8:	3c 32                	cmp    al,0x32
   140005bda:	75 0e                	jne    140005bea <__mingw_pformat+0x9f7>
   140005bdc:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005be3:	48 83 45 28 02       	add    QWORD PTR [rbp+0x28],0x2
   140005be8:	eb 07                	jmp    140005bf1 <__mingw_pformat+0x9fe>
   140005bea:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005bf1:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005bf8:	e9 78 02 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005bfd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005c01:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005c04:	3c 6c                	cmp    al,0x6c
   140005c06:	75 0e                	jne    140005c16 <__mingw_pformat+0xa23>
   140005c08:	48 83 45 28 01       	add    QWORD PTR [rbp+0x28],0x1
   140005c0d:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c14:	eb 07                	jmp    140005c1d <__mingw_pformat+0xa2a>
   140005c16:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005c1d:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c24:	e9 4c 02 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005c29:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140005c30:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c37:	e9 39 02 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005c3c:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005c3f:	83 c8 04             	or     eax,0x4
   140005c42:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005c45:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c4c:	e9 24 02 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005c51:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c58:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c5f:	e9 11 02 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005c64:	c7 45 f8 03 00 00 00 	mov    DWORD PTR [rbp-0x8],0x3
   140005c6b:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005c72:	e9 fe 01 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005c77:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140005c7b:	77 1f                	ja     140005c9c <__mingw_pformat+0xaa9>
   140005c7d:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140005c84:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005c88:	48 83 c0 10          	add    rax,0x10
   140005c8c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005c90:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   140005c97:	e9 d9 01 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005c9c:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ca3:	e9 cd 01 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005ca8:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005cad:	74 4c                	je     140005cfb <__mingw_pformat+0xb08>
   140005caf:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cb3:	74 06                	je     140005cbb <__mingw_pformat+0xac8>
   140005cb5:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005cb9:	75 40                	jne    140005cfb <__mingw_pformat+0xb08>
   140005cbb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140005cbf:	48 8d 50 08          	lea    rdx,[rax+0x8]
   140005cc3:	48 89 55 30          	mov    QWORD PTR [rbp+0x30],rdx
   140005cc7:	8b 10                	mov    edx,DWORD PTR [rax]
   140005cc9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005ccd:	89 10                	mov    DWORD PTR [rax],edx
   140005ccf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005cd3:	8b 00                	mov    eax,DWORD PTR [rax]
   140005cd5:	85 c0                	test   eax,eax
   140005cd7:	79 29                	jns    140005d02 <__mingw_pformat+0xb0f>
   140005cd9:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005cdd:	75 13                	jne    140005cf2 <__mingw_pformat+0xaff>
   140005cdf:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005ce2:	80 cc 04             	or     ah,0x4
   140005ce5:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005ce8:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140005ceb:	f7 d8                	neg    eax
   140005ced:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140005cf0:	eb 10                	jmp    140005d02 <__mingw_pformat+0xb0f>
   140005cf2:	c7 45 b0 ff ff ff ff 	mov    DWORD PTR [rbp-0x50],0xffffffff
   140005cf9:	eb 07                	jmp    140005d02 <__mingw_pformat+0xb0f>
   140005cfb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005d02:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
   140005d09:	00 
   140005d0a:	e9 66 01 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005d0f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d13:	0f 85 4f 01 00 00    	jne    140005e68 <__mingw_pformat+0xc75>
   140005d19:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d1c:	80 cc 08             	or     ah,0x8
   140005d1f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d22:	e9 41 01 00 00       	jmp    140005e68 <__mingw_pformat+0xc75>
   140005d27:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d2b:	0f 85 3a 01 00 00    	jne    140005e6b <__mingw_pformat+0xc78>
   140005d31:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d34:	80 cc 01             	or     ah,0x1
   140005d37:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d3a:	e9 2c 01 00 00       	jmp    140005e6b <__mingw_pformat+0xc78>
   140005d3f:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d43:	0f 85 25 01 00 00    	jne    140005e6e <__mingw_pformat+0xc7b>
   140005d49:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d4c:	80 cc 04             	or     ah,0x4
   140005d4f:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d52:	e9 17 01 00 00       	jmp    140005e6e <__mingw_pformat+0xc7b>
   140005d57:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005d5b:	0f 85 10 01 00 00    	jne    140005e71 <__mingw_pformat+0xc7e>
   140005d61:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005d64:	80 cc 10             	or     ah,0x10
   140005d67:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005d6a:	48 c7 45 84 00 00 00 	mov    QWORD PTR [rbp-0x7c],0x0
   140005d71:	00 
   140005d72:	e8 a1 39 00 00       	call   140009718 <localeconv>
   140005d77:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
   140005d7b:	48 8d 4d 84          	lea    rcx,[rbp-0x7c]
   140005d7f:	48 8d 45 8c          	lea    rax,[rbp-0x74]
   140005d83:	49 89 c9             	mov    r9,rcx
   140005d86:	41 b8 10 00 00 00    	mov    r8d,0x10
   140005d8c:	48 89 c1             	mov    rcx,rax
   140005d8f:	e8 bc 33 00 00       	call   140009150 <mbrtowc>
   140005d94:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140005d97:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   140005d9b:	7e 08                	jle    140005da5 <__mingw_pformat+0xbb2>
   140005d9d:	0f b7 45 8c          	movzx  eax,WORD PTR [rbp-0x74]
   140005da1:	66 89 45 c0          	mov    WORD PTR [rbp-0x40],ax
   140005da5:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140005da8:	89 45 bc             	mov    DWORD PTR [rbp-0x44],eax
   140005dab:	e9 c1 00 00 00       	jmp    140005e71 <__mingw_pformat+0xc7e>
   140005db0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005db4:	0f 85 ba 00 00 00    	jne    140005e74 <__mingw_pformat+0xc81>
   140005dba:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005dbd:	83 c8 40             	or     eax,0x40
   140005dc0:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005dc3:	e9 ac 00 00 00       	jmp    140005e74 <__mingw_pformat+0xc81>
   140005dc8:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005dcc:	75 0e                	jne    140005ddc <__mingw_pformat+0xbe9>
   140005dce:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
   140005dd1:	80 cc 02             	or     ah,0x2
   140005dd4:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
   140005dd7:	e9 99 00 00 00       	jmp    140005e75 <__mingw_pformat+0xc82>
   140005ddc:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
   140005de0:	77 68                	ja     140005e4a <__mingw_pformat+0xc57>
   140005de2:	83 7d e8 39          	cmp    DWORD PTR [rbp-0x18],0x39
   140005de6:	7f 62                	jg     140005e4a <__mingw_pformat+0xc57>
   140005de8:	83 7d e8 2f          	cmp    DWORD PTR [rbp-0x18],0x2f
   140005dec:	7e 5c                	jle    140005e4a <__mingw_pformat+0xc57>
   140005dee:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140005df2:	75 09                	jne    140005dfd <__mingw_pformat+0xc0a>
   140005df4:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140005dfb:	eb 0d                	jmp    140005e0a <__mingw_pformat+0xc17>
   140005dfd:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   140005e01:	75 07                	jne    140005e0a <__mingw_pformat+0xc17>
   140005e03:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [rbp-0x4],0x3
   140005e0a:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140005e0f:	74 64                	je     140005e75 <__mingw_pformat+0xc82>
   140005e11:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e15:	8b 00                	mov    eax,DWORD PTR [rax]
   140005e17:	85 c0                	test   eax,eax
   140005e19:	79 0e                	jns    140005e29 <__mingw_pformat+0xc36>
   140005e1b:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e1e:	8d 50 d0             	lea    edx,[rax-0x30]
   140005e21:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e25:	89 10                	mov    DWORD PTR [rax],edx
   140005e27:	eb 4c                	jmp    140005e75 <__mingw_pformat+0xc82>
   140005e29:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e2d:	8b 10                	mov    edx,DWORD PTR [rax]
   140005e2f:	89 d0                	mov    eax,edx
   140005e31:	c1 e0 02             	shl    eax,0x2
   140005e34:	01 d0                	add    eax,edx
   140005e36:	01 c0                	add    eax,eax
   140005e38:	89 c2                	mov    edx,eax
   140005e3a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e3d:	01 d0                	add    eax,edx
   140005e3f:	8d 50 d0             	lea    edx,[rax-0x30]
   140005e42:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005e46:	89 10                	mov    DWORD PTR [rax],edx
   140005e48:	eb 2b                	jmp    140005e75 <__mingw_pformat+0xc82>
   140005e4a:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140005e4e:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140005e52:	48 8d 45 a0          	lea    rax,[rbp-0x60]
   140005e56:	48 89 c2             	mov    rdx,rax
   140005e59:	b9 25 00 00 00       	mov    ecx,0x25
   140005e5e:	e8 fd d3 ff ff       	call   140003260 <__pformat_putc>
   140005e63:	e9 00 f4 ff ff       	jmp    140005268 <__mingw_pformat+0x75>
   140005e68:	90                   	nop
   140005e69:	eb 0a                	jmp    140005e75 <__mingw_pformat+0xc82>
   140005e6b:	90                   	nop
   140005e6c:	eb 07                	jmp    140005e75 <__mingw_pformat+0xc82>
   140005e6e:	90                   	nop
   140005e6f:	eb 04                	jmp    140005e75 <__mingw_pformat+0xc82>
   140005e71:	90                   	nop
   140005e72:	eb 01                	jmp    140005e75 <__mingw_pformat+0xc82>
   140005e74:	90                   	nop
   140005e75:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e79:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005e7c:	84 c0                	test   al,al
   140005e7e:	0f 85 2d f4 ff ff    	jne    1400052b1 <__mingw_pformat+0xbe>
   140005e84:	eb 0e                	jmp    140005e94 <__mingw_pformat+0xca1>
   140005e86:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
   140005e8a:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140005e8d:	89 c1                	mov    ecx,eax
   140005e8f:	e8 cc d3 ff ff       	call   140003260 <__pformat_putc>
   140005e94:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140005e98:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005e9c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140005ea0:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005ea3:	0f be c0             	movsx  eax,al
   140005ea6:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140005ea9:	83 7d e8 00          	cmp    DWORD PTR [rbp-0x18],0x0
   140005ead:	0f 85 ba f3 ff ff    	jne    14000526d <__mingw_pformat+0x7a>
   140005eb3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140005eb6:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
   140005ebd:	5d                   	pop    rbp
   140005ebe:	c3                   	ret
   140005ebf:	90                   	nop

0000000140005ec0 <__rv_alloc_D2A>:
   140005ec0:	55                   	push   rbp
   140005ec1:	48 89 e5             	mov    rbp,rsp
   140005ec4:	48 83 ec 30          	sub    rsp,0x30
   140005ec8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140005ecb:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [rbp-0x4],0x4
   140005ed2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140005ed9:	eb 07                	jmp    140005ee2 <__rv_alloc_D2A+0x22>
   140005edb:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   140005edf:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140005ee2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140005ee5:	83 c0 17             	add    eax,0x17
   140005ee8:	39 45 10             	cmp    DWORD PTR [rbp+0x10],eax
   140005eeb:	7f ee                	jg     140005edb <__rv_alloc_D2A+0x1b>
   140005eed:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140005ef0:	89 c1                	mov    ecx,eax
   140005ef2:	e8 56 1e 00 00       	call   140007d4d <__Balloc_D2A>
   140005ef7:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005efb:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005eff:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140005f02:	89 10                	mov    DWORD PTR [rax],edx
   140005f04:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f08:	48 83 c0 04          	add    rax,0x4
   140005f0c:	48 83 c4 30          	add    rsp,0x30
   140005f10:	5d                   	pop    rbp
   140005f11:	c3                   	ret

0000000140005f12 <__nrv_alloc_D2A>:
   140005f12:	55                   	push   rbp
   140005f13:	48 89 e5             	mov    rbp,rsp
   140005f16:	48 83 ec 30          	sub    rsp,0x30
   140005f1a:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f1e:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005f22:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140005f26:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140005f29:	89 c1                	mov    ecx,eax
   140005f2b:	e8 90 ff ff ff       	call   140005ec0 <__rv_alloc_D2A>
   140005f30:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140005f34:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f38:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f3c:	eb 05                	jmp    140005f43 <__nrv_alloc_D2A+0x31>
   140005f3e:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140005f43:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f47:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140005f4b:	48 89 55 10          	mov    QWORD PTR [rbp+0x10],rdx
   140005f4f:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140005f52:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f56:	88 10                	mov    BYTE PTR [rax],dl
   140005f58:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f5c:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140005f5f:	84 c0                	test   al,al
   140005f61:	75 db                	jne    140005f3e <__nrv_alloc_D2A+0x2c>
   140005f63:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140005f68:	74 0b                	je     140005f75 <__nrv_alloc_D2A+0x63>
   140005f6a:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005f6e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140005f72:	48 89 10             	mov    QWORD PTR [rax],rdx
   140005f75:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140005f79:	48 83 c4 30          	add    rsp,0x30
   140005f7d:	5d                   	pop    rbp
   140005f7e:	c3                   	ret

0000000140005f7f <__freedtoa>:
   140005f7f:	55                   	push   rbp
   140005f80:	48 89 e5             	mov    rbp,rsp
   140005f83:	48 83 ec 30          	sub    rsp,0x30
   140005f87:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005f8b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005f8f:	48 83 e8 04          	sub    rax,0x4
   140005f93:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140005f97:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005f9b:	8b 10                	mov    edx,DWORD PTR [rax]
   140005f9d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fa1:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140005fa4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fa8:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140005fab:	ba 01 00 00 00       	mov    edx,0x1
   140005fb0:	89 c1                	mov    ecx,eax
   140005fb2:	d3 e2                	shl    edx,cl
   140005fb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fb8:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140005fbb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140005fbf:	48 89 c1             	mov    rcx,rax
   140005fc2:	e8 c7 1e 00 00       	call   140007e8e <__Bfree_D2A>
   140005fc7:	90                   	nop
   140005fc8:	48 83 c4 30          	add    rsp,0x30
   140005fcc:	5d                   	pop    rbp
   140005fcd:	c3                   	ret

0000000140005fce <__quorem_D2A>:
   140005fce:	55                   	push   rbp
   140005fcf:	48 89 e5             	mov    rbp,rsp
   140005fd2:	48 83 ec 70          	sub    rsp,0x70
   140005fd6:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140005fda:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140005fde:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140005fe2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005fe5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140005fe8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140005fec:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140005fef:	39 45 fc             	cmp    DWORD PTR [rbp-0x4],eax
   140005ff2:	7e 0a                	jle    140005ffe <__quorem_D2A+0x30>
   140005ff4:	b8 00 00 00 00       	mov    eax,0x0
   140005ff9:	e9 3f 02 00 00       	jmp    14000623d <__quorem_D2A+0x26f>
   140005ffe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006002:	48 83 c0 18          	add    rax,0x18
   140006006:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000600a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000600e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006011:	48 98                	cdqe
   140006013:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000601a:	00 
   14000601b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000601f:	48 01 d0             	add    rax,rdx
   140006022:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140006026:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000602a:	48 83 c0 18          	add    rax,0x18
   14000602e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006032:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006035:	48 98                	cdqe
   140006037:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000603e:	00 
   14000603f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006043:	48 01 d0             	add    rax,rdx
   140006046:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000604a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000604e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006050:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   140006054:	8b 12                	mov    edx,DWORD PTR [rdx]
   140006056:	8d 4a 01             	lea    ecx,[rdx+0x1]
   140006059:	ba 00 00 00 00       	mov    edx,0x0
   14000605e:	f7 f1                	div    ecx
   140006060:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140006063:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140006067:	0f 84 c4 00 00 00    	je     140006131 <__quorem_D2A+0x163>
   14000606d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006074:	00 
   140006075:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000607c:	00 
   14000607d:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006081:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140006085:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006089:	8b 00                	mov    eax,DWORD PTR [rax]
   14000608b:	89 c2                	mov    edx,eax
   14000608d:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140006090:	48 0f af d0          	imul   rdx,rax
   140006094:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006098:	48 01 d0             	add    rax,rdx
   14000609b:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000609f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060a3:	48 c1 e8 20          	shr    rax,0x20
   1400060a7:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400060ab:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060af:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060b1:	89 c1                	mov    ecx,eax
   1400060b3:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400060b7:	89 c2                	mov    edx,eax
   1400060b9:	48 89 c8             	mov    rax,rcx
   1400060bc:	48 29 d0             	sub    rax,rdx
   1400060bf:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400060c3:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400060c7:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400060cb:	48 c1 e8 20          	shr    rax,0x20
   1400060cf:	83 e0 01             	and    eax,0x1
   1400060d2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400060d6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400060da:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400060de:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400060e2:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400060e6:	89 10                	mov    DWORD PTR [rax],edx
   1400060e8:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400060ec:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400060f0:	73 8b                	jae    14000607d <__quorem_D2A+0xaf>
   1400060f2:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400060f6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400060f8:	85 c0                	test   eax,eax
   1400060fa:	75 35                	jne    140006131 <__quorem_D2A+0x163>
   1400060fc:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006100:	48 83 c0 18          	add    rax,0x18
   140006104:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006108:	eb 04                	jmp    14000610e <__quorem_D2A+0x140>
   14000610a:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000610e:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   140006113:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006117:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   14000611b:	73 0a                	jae    140006127 <__quorem_D2A+0x159>
   14000611d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006121:	8b 00                	mov    eax,DWORD PTR [rax]
   140006123:	85 c0                	test   eax,eax
   140006125:	74 e3                	je     14000610a <__quorem_D2A+0x13c>
   140006127:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000612b:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000612e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006131:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140006135:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006139:	48 89 c1             	mov    rcx,rax
   14000613c:	e8 bc 24 00 00       	call   1400085fd <__cmp_D2A>
   140006141:	85 c0                	test   eax,eax
   140006143:	0f 88 f1 00 00 00    	js     14000623a <__quorem_D2A+0x26c>
   140006149:	83 45 e4 01          	add    DWORD PTR [rbp-0x1c],0x1
   14000614d:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   140006154:	00 
   140006155:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
   14000615c:	00 
   14000615d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006161:	48 83 c0 18          	add    rax,0x18
   140006165:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140006169:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000616d:	48 83 c0 18          	add    rax,0x18
   140006171:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140006175:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140006179:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000617d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
   140006181:	8b 00                	mov    eax,DWORD PTR [rax]
   140006183:	89 c2                	mov    edx,eax
   140006185:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140006189:	48 01 d0             	add    rax,rdx
   14000618c:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140006190:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   140006194:	48 c1 e8 20          	shr    rax,0x20
   140006198:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   14000619c:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061a0:	8b 00                	mov    eax,DWORD PTR [rax]
   1400061a2:	89 c1                	mov    ecx,eax
   1400061a4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400061a8:	89 c2                	mov    edx,eax
   1400061aa:	48 89 c8             	mov    rax,rcx
   1400061ad:	48 29 d0             	sub    rax,rdx
   1400061b0:	48 2b 45 d0          	sub    rax,QWORD PTR [rbp-0x30]
   1400061b4:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   1400061b8:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   1400061bc:	48 c1 e8 20          	shr    rax,0x20
   1400061c0:	83 e0 01             	and    eax,0x1
   1400061c3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400061c7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400061cb:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400061cf:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400061d3:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   1400061d7:	89 10                	mov    DWORD PTR [rax],edx
   1400061d9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400061dd:	48 39 45 c0          	cmp    QWORD PTR [rbp-0x40],rax
   1400061e1:	73 92                	jae    140006175 <__quorem_D2A+0x1a7>
   1400061e3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400061e7:	48 83 c0 18          	add    rax,0x18
   1400061eb:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400061ef:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400061f2:	48 98                	cdqe
   1400061f4:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400061fb:	00 
   1400061fc:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140006200:	48 01 d0             	add    rax,rdx
   140006203:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140006207:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000620b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000620d:	85 c0                	test   eax,eax
   14000620f:	75 29                	jne    14000623a <__quorem_D2A+0x26c>
   140006211:	eb 04                	jmp    140006217 <__quorem_D2A+0x249>
   140006213:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   140006217:	48 83 6d e8 04       	sub    QWORD PTR [rbp-0x18],0x4
   14000621c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006220:	48 39 45 f0          	cmp    QWORD PTR [rbp-0x10],rax
   140006224:	73 0a                	jae    140006230 <__quorem_D2A+0x262>
   140006226:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000622a:	8b 00                	mov    eax,DWORD PTR [rax]
   14000622c:	85 c0                	test   eax,eax
   14000622e:	74 e3                	je     140006213 <__quorem_D2A+0x245>
   140006230:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140006234:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006237:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000623a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   14000623d:	48 83 c4 70          	add    rsp,0x70
   140006241:	5d                   	pop    rbp
   140006242:	c3                   	ret
   140006243:	90                   	nop
   140006244:	90                   	nop
   140006245:	90                   	nop
   140006246:	90                   	nop
   140006247:	90                   	nop
   140006248:	90                   	nop
   140006249:	90                   	nop
   14000624a:	90                   	nop
   14000624b:	90                   	nop
   14000624c:	90                   	nop
   14000624d:	90                   	nop
   14000624e:	90                   	nop
   14000624f:	90                   	nop

0000000140006250 <__hi0bits_D2A>:
   140006250:	55                   	push   rbp
   140006251:	48 89 e5             	mov    rbp,rsp
   140006254:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140006257:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   14000625b:	83 f0 1f             	xor    eax,0x1f
   14000625e:	5d                   	pop    rbp
   14000625f:	c3                   	ret

0000000140006260 <bitstob>:
   140006260:	55                   	push   rbp
   140006261:	53                   	push   rbx
   140006262:	48 83 ec 58          	sub    rsp,0x58
   140006266:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   14000626b:	48 89 4d 20          	mov    QWORD PTR [rbp+0x20],rcx
   14000626f:	89 55 28             	mov    DWORD PTR [rbp+0x28],edx
   140006272:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140006276:	c7 45 fc 20 00 00 00 	mov    DWORD PTR [rbp-0x4],0x20
   14000627d:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   140006284:	eb 07                	jmp    14000628d <bitstob+0x2d>
   140006286:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   140006289:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   14000628d:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006290:	3b 45 28             	cmp    eax,DWORD PTR [rbp+0x28]
   140006293:	7c f1                	jl     140006286 <bitstob+0x26>
   140006295:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140006298:	89 c1                	mov    ecx,eax
   14000629a:	e8 ae 1a 00 00       	call   140007d4d <__Balloc_D2A>
   14000629f:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400062a3:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   1400062a6:	83 e8 01             	sub    eax,0x1
   1400062a9:	c1 f8 05             	sar    eax,0x5
   1400062ac:	48 98                	cdqe
   1400062ae:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400062b5:	00 
   1400062b6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400062ba:	48 01 d0             	add    rax,rdx
   1400062bd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400062c1:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400062c5:	48 83 c0 18          	add    rax,0x18
   1400062c9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400062cd:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400062d1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400062d5:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062d9:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400062dd:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400062e1:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   1400062e5:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400062e7:	89 10                	mov    DWORD PTR [rax],edx
   1400062e9:	48 83 45 20 04       	add    QWORD PTR [rbp+0x20],0x4
   1400062ee:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400062f2:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400062f6:	73 dd                	jae    1400062d5 <bitstob+0x75>
   1400062f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400062fc:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140006300:	48 c1 f8 02          	sar    rax,0x2
   140006304:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140006307:	eb 1d                	jmp    140006326 <bitstob+0xc6>
   140006309:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   14000630d:	75 17                	jne    140006326 <bitstob+0xc6>
   14000630f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006313:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   14000631a:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000631e:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140006324:	eb 59                	jmp    14000637f <bitstob+0x11f>
   140006326:	83 6d fc 01          	sub    DWORD PTR [rbp-0x4],0x1
   14000632a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000632d:	48 98                	cdqe
   14000632f:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140006336:	00 
   140006337:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000633b:	48 01 d0             	add    rax,rdx
   14000633e:	8b 00                	mov    eax,DWORD PTR [rax]
   140006340:	85 c0                	test   eax,eax
   140006342:	74 c5                	je     140006309 <bitstob+0xa9>
   140006344:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006347:	8d 50 01             	lea    edx,[rax+0x1]
   14000634a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000634e:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140006351:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140006354:	83 c0 01             	add    eax,0x1
   140006357:	c1 e0 05             	shl    eax,0x5
   14000635a:	89 c3                	mov    ebx,eax
   14000635c:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006360:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140006363:	48 63 d2             	movsxd rdx,edx
   140006366:	48 83 c2 04          	add    rdx,0x4
   14000636a:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   14000636e:	89 c1                	mov    ecx,eax
   140006370:	e8 db fe ff ff       	call   140006250 <__hi0bits_D2A>
   140006375:	29 c3                	sub    ebx,eax
   140006377:	89 da                	mov    edx,ebx
   140006379:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   14000637d:	89 10                	mov    DWORD PTR [rax],edx
   14000637f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006383:	48 83 c4 58          	add    rsp,0x58
   140006387:	5b                   	pop    rbx
   140006388:	5d                   	pop    rbp
   140006389:	c3                   	ret

000000014000638a <__gdtoa>:
   14000638a:	55                   	push   rbp
   14000638b:	48 81 ec 00 01 00 00 	sub    rsp,0x100
   140006392:	48 8d ac 24 80 00 00 	lea    rbp,[rsp+0x80]
   140006399:	00 
   14000639a:	48 89 8d 90 00 00 00 	mov    QWORD PTR [rbp+0x90],rcx
   1400063a1:	89 95 98 00 00 00    	mov    DWORD PTR [rbp+0x98],edx
   1400063a7:	4c 89 85 a0 00 00 00 	mov    QWORD PTR [rbp+0xa0],r8
   1400063ae:	4c 89 8d a8 00 00 00 	mov    QWORD PTR [rbp+0xa8],r9
   1400063b5:	c7 45 64 00 00 00 00 	mov    DWORD PTR [rbp+0x64],0x0
   1400063bc:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063c3:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063c5:	83 e0 cf             	and    eax,0xffffffcf
   1400063c8:	89 c2                	mov    edx,eax
   1400063ca:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063d1:	89 10                	mov    DWORD PTR [rax],edx
   1400063d3:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400063da:	8b 00                	mov    eax,DWORD PTR [rax]
   1400063dc:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400063df:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400063e2:	83 e0 07             	and    eax,0x7
   1400063e5:	83 f8 04             	cmp    eax,0x4
   1400063e8:	0f 84 b0 00 00 00    	je     14000649e <__gdtoa+0x114>
   1400063ee:	83 f8 04             	cmp    eax,0x4
   1400063f1:	0f 8f d5 00 00 00    	jg     1400064cc <__gdtoa+0x142>
   1400063f7:	83 f8 03             	cmp    eax,0x3
   1400063fa:	74 74                	je     140006470 <__gdtoa+0xe6>
   1400063fc:	83 f8 03             	cmp    eax,0x3
   1400063ff:	0f 8f c7 00 00 00    	jg     1400064cc <__gdtoa+0x142>
   140006405:	85 c0                	test   eax,eax
   140006407:	0f 84 05 01 00 00    	je     140006512 <__gdtoa+0x188>
   14000640d:	85 c0                	test   eax,eax
   14000640f:	0f 88 b7 00 00 00    	js     1400064cc <__gdtoa+0x142>
   140006415:	83 e8 01             	sub    eax,0x1
   140006418:	83 f8 01             	cmp    eax,0x1
   14000641b:	0f 87 ab 00 00 00    	ja     1400064cc <__gdtoa+0x142>
   140006421:	90                   	nop
   140006422:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006429:	8b 00                	mov    eax,DWORD PTR [rax]
   14000642b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000642e:	48 8d 4d b4          	lea    rcx,[rbp-0x4c]
   140006432:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006435:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   14000643c:	49 89 c8             	mov    r8,rcx
   14000643f:	48 89 c1             	mov    rcx,rax
   140006442:	e8 19 fe ff ff       	call   140006260 <bitstob>
   140006447:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000644b:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006451:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140006454:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006458:	48 89 c1             	mov    rcx,rax
   14000645b:	e8 31 16 00 00       	call   140007a91 <__trailz_D2A>
   140006460:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006463:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006466:	85 c0                	test   eax,eax
   140006468:	0f 84 8b 00 00 00    	je     1400064f9 <__gdtoa+0x16f>
   14000646e:	eb 66                	jmp    1400064d6 <__gdtoa+0x14c>
   140006470:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   140006477:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   14000647d:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006484:	48 8d 0d e5 4e 00 00 	lea    rcx,[rip+0x4ee5]        # 14000b370 <.rdata>
   14000648b:	41 b8 08 00 00 00    	mov    r8d,0x8
   140006491:	48 89 c2             	mov    rdx,rax
   140006494:	e8 79 fa ff ff       	call   140005f12 <__nrv_alloc_D2A>
   140006499:	e9 4d 14 00 00       	jmp    1400078eb <__gdtoa+0x1561>
   14000649e:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400064a5:	c7 00 00 80 ff ff    	mov    DWORD PTR [rax],0xffff8000
   1400064ab:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400064b2:	48 8d 0d c0 4e 00 00 	lea    rcx,[rip+0x4ec0]        # 14000b379 <.rdata+0x9>
   1400064b9:	41 b8 03 00 00 00    	mov    r8d,0x3
   1400064bf:	48 89 c2             	mov    rdx,rax
   1400064c2:	e8 4b fa ff ff       	call   140005f12 <__nrv_alloc_D2A>
   1400064c7:	e9 1f 14 00 00       	jmp    1400078eb <__gdtoa+0x1561>
   1400064cc:	b8 00 00 00 00       	mov    eax,0x0
   1400064d1:	e9 15 14 00 00       	jmp    1400078eb <__gdtoa+0x1561>
   1400064d6:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   1400064d9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064dd:	48 89 c1             	mov    rcx,rax
   1400064e0:	e8 50 14 00 00       	call   140007935 <__rshift_D2A>
   1400064e5:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064e8:	01 85 98 00 00 00    	add    DWORD PTR [rbp+0x98],eax
   1400064ee:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   1400064f1:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400064f4:	29 c2                	sub    edx,eax
   1400064f6:	89 55 b4             	mov    DWORD PTR [rbp-0x4c],edx
   1400064f9:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400064fd:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006500:	85 c0                	test   eax,eax
   140006502:	75 3d                	jne    140006541 <__gdtoa+0x1b7>
   140006504:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006508:	48 89 c1             	mov    rcx,rax
   14000650b:	e8 7e 19 00 00       	call   140007e8e <__Bfree_D2A>
   140006510:	eb 01                	jmp    140006513 <__gdtoa+0x189>
   140006512:	90                   	nop
   140006513:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   14000651a:	c7 00 01 00 00 00    	mov    DWORD PTR [rax],0x1
   140006520:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   140006527:	48 8d 0d 4f 4e 00 00 	lea    rcx,[rip+0x4e4f]        # 14000b37d <.rdata+0xd>
   14000652e:	41 b8 01 00 00 00    	mov    r8d,0x1
   140006534:	48 89 c2             	mov    rdx,rax
   140006537:	e8 d6 f9 ff ff       	call   140005f12 <__nrv_alloc_D2A>
   14000653c:	e9 aa 13 00 00       	jmp    1400078eb <__gdtoa+0x1561>
   140006541:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
   140006545:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140006549:	48 89 c1             	mov    rcx,rax
   14000654c:	e8 75 23 00 00       	call   1400088c6 <__b2d_D2A>
   140006551:	66 48 0f 7e c0       	movq   rax,xmm0
   140006556:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   14000655a:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   14000655d:	8b 85 98 00 00 00    	mov    eax,DWORD PTR [rbp+0x98]
   140006563:	01 d0                	add    eax,edx
   140006565:	83 e8 01             	sub    eax,0x1
   140006568:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000656b:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   14000656e:	25 ff ff 0f 00       	and    eax,0xfffff
   140006573:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006576:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006579:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   14000657e:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   140006581:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006586:	f2 0f 10 15 f2 4d 00 	movsd  xmm2,QWORD PTR [rip+0x4df2]        # 14000b380 <.rdata+0x10>
   14000658d:	00 
   14000658e:	66 0f 28 c8          	movapd xmm1,xmm0
   140006592:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006596:	f2 0f 10 05 ea 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4dea]        # 14000b388 <.rdata+0x18>
   14000659d:	00 
   14000659e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   1400065a2:	f2 0f 10 05 e6 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4de6]        # 14000b390 <.rdata+0x20>
   1400065a9:	00 
   1400065aa:	f2 0f 58 c8          	addsd  xmm1,xmm0
   1400065ae:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065b1:	66 0f ef d2          	pxor   xmm2,xmm2
   1400065b5:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
   1400065b9:	f2 0f 10 05 d7 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4dd7]        # 14000b398 <.rdata+0x28>
   1400065c0:	00 
   1400065c1:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   1400065c5:	f2 0f 58 c1          	addsd  xmm0,xmm1
   1400065c9:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400065ce:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400065d1:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400065d4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065d8:	79 03                	jns    1400065dd <__gdtoa+0x253>
   1400065da:	f7 5d 60             	neg    DWORD PTR [rbp+0x60]
   1400065dd:	81 6d 60 35 04 00 00 	sub    DWORD PTR [rbp+0x60],0x435
   1400065e4:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400065e8:	7e 23                	jle    14000660d <__gdtoa+0x283>
   1400065ea:	66 0f ef c9          	pxor   xmm1,xmm1
   1400065ee:	f2 0f 2a 4d 60       	cvtsi2sd xmm1,DWORD PTR [rbp+0x60]
   1400065f3:	f2 0f 10 05 a5 4d 00 	movsd  xmm0,QWORD PTR [rip+0x4da5]        # 14000b3a0 <.rdata+0x30>
   1400065fa:	00 
   1400065fb:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400065ff:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006604:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006608:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000660d:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006612:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006616:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006619:	66 0f ef c0          	pxor   xmm0,xmm0
   14000661d:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006622:	76 1b                	jbe    14000663f <__gdtoa+0x2b5>
   140006624:	66 0f ef c0          	pxor   xmm0,xmm0
   140006628:	f2 0f 2a 45 58       	cvtsi2sd xmm0,DWORD PTR [rbp+0x58]
   14000662d:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006632:	7a 07                	jp     14000663b <__gdtoa+0x2b1>
   140006634:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006639:	74 04                	je     14000663f <__gdtoa+0x2b5>
   14000663b:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000663f:	c7 45 54 01 00 00 00 	mov    DWORD PTR [rbp+0x54],0x1
   140006646:	8b 45 ac             	mov    eax,DWORD PTR [rbp-0x54]
   140006649:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
   14000664c:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006652:	01 ca                	add    edx,ecx
   140006654:	83 ea 01             	sub    edx,0x1
   140006657:	c1 e2 14             	shl    edx,0x14
   14000665a:	01 d0                	add    eax,edx
   14000665c:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
   14000665f:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   140006663:	78 2e                	js     140006693 <__gdtoa+0x309>
   140006665:	83 7d 58 16          	cmp    DWORD PTR [rbp+0x58],0x16
   140006669:	7f 28                	jg     140006693 <__gdtoa+0x309>
   14000666b:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006670:	48 8b 05 29 50 00 00 	mov    rax,QWORD PTR [rip+0x5029]        # 14000b6a0 <.refptr.__tens_D2A>
   140006677:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   14000667a:	48 63 d2             	movsxd rdx,edx
   14000667d:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006682:	66 0f 2f c1          	comisd xmm0,xmm1
   140006686:	76 04                	jbe    14000668c <__gdtoa+0x302>
   140006688:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   14000668c:	c7 45 54 00 00 00 00 	mov    DWORD PTR [rbp+0x54],0x0
   140006693:	8b 55 b4             	mov    edx,DWORD PTR [rbp-0x4c]
   140006696:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006699:	29 c2                	sub    edx,eax
   14000669b:	8d 42 ff             	lea    eax,[rdx-0x1]
   14000669e:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400066a1:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400066a5:	78 0f                	js     1400066b6 <__gdtoa+0x32c>
   1400066a7:	c7 45 7c 00 00 00 00 	mov    DWORD PTR [rbp+0x7c],0x0
   1400066ae:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400066b1:	89 45 40             	mov    DWORD PTR [rbp+0x40],eax
   1400066b4:	eb 0f                	jmp    1400066c5 <__gdtoa+0x33b>
   1400066b6:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   1400066b9:	f7 d8                	neg    eax
   1400066bb:	89 45 7c             	mov    DWORD PTR [rbp+0x7c],eax
   1400066be:	c7 45 40 00 00 00 00 	mov    DWORD PTR [rbp+0x40],0x0
   1400066c5:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400066c9:	78 15                	js     1400066e0 <__gdtoa+0x356>
   1400066cb:	c7 45 78 00 00 00 00 	mov    DWORD PTR [rbp+0x78],0x0
   1400066d2:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066d5:	89 45 3c             	mov    DWORD PTR [rbp+0x3c],eax
   1400066d8:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066db:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400066de:	eb 15                	jmp    1400066f5 <__gdtoa+0x36b>
   1400066e0:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066e3:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   1400066e6:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400066e9:	f7 d8                	neg    eax
   1400066eb:	89 45 78             	mov    DWORD PTR [rbp+0x78],eax
   1400066ee:	c7 45 3c 00 00 00 00 	mov    DWORD PTR [rbp+0x3c],0x0
   1400066f5:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400066fc:	78 09                	js     140006707 <__gdtoa+0x37d>
   1400066fe:	83 bd b0 00 00 00 09 	cmp    DWORD PTR [rbp+0xb0],0x9
   140006705:	7e 0a                	jle    140006711 <__gdtoa+0x387>
   140006707:	c7 85 b0 00 00 00 00 	mov    DWORD PTR [rbp+0xb0],0x0
   14000670e:	00 00 00 
   140006711:	c7 45 34 01 00 00 00 	mov    DWORD PTR [rbp+0x34],0x1
   140006718:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   14000671f:	7e 10                	jle    140006731 <__gdtoa+0x3a7>
   140006721:	83 ad b0 00 00 00 04 	sub    DWORD PTR [rbp+0xb0],0x4
   140006728:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000672f:	eb 1b                	jmp    14000674c <__gdtoa+0x3c2>
   140006731:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006734:	3d f9 03 00 00       	cmp    eax,0x3f9
   140006739:	7f 0a                	jg     140006745 <__gdtoa+0x3bb>
   14000673b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000673e:	3d 02 fc ff ff       	cmp    eax,0xfffffc02
   140006743:	7d 07                	jge    14000674c <__gdtoa+0x3c2>
   140006745:	c7 45 34 00 00 00 00 	mov    DWORD PTR [rbp+0x34],0x0
   14000674c:	c7 45 50 01 00 00 00 	mov    DWORD PTR [rbp+0x50],0x1
   140006753:	c7 45 68 ff ff ff ff 	mov    DWORD PTR [rbp+0x68],0xffffffff
   14000675a:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000675d:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006760:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006767:	0f 84 c5 00 00 00    	je     140006832 <__gdtoa+0x4a8>
   14000676d:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006774:	0f 8f e6 00 00 00    	jg     140006860 <__gdtoa+0x4d6>
   14000677a:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   140006781:	74 7e                	je     140006801 <__gdtoa+0x477>
   140006783:	83 bd b0 00 00 00 04 	cmp    DWORD PTR [rbp+0xb0],0x4
   14000678a:	0f 8f d0 00 00 00    	jg     140006860 <__gdtoa+0x4d6>
   140006790:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006797:	0f 84 8e 00 00 00    	je     14000682b <__gdtoa+0x4a1>
   14000679d:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   1400067a4:	0f 8f b6 00 00 00    	jg     140006860 <__gdtoa+0x4d6>
   1400067aa:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   1400067b1:	7f 0e                	jg     1400067c1 <__gdtoa+0x437>
   1400067b3:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400067ba:	79 13                	jns    1400067cf <__gdtoa+0x445>
   1400067bc:	e9 9f 00 00 00       	jmp    140006860 <__gdtoa+0x4d6>
   1400067c1:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   1400067c8:	74 30                	je     1400067fa <__gdtoa+0x470>
   1400067ca:	e9 91 00 00 00       	jmp    140006860 <__gdtoa+0x4d6>
   1400067cf:	66 0f ef c9          	pxor   xmm1,xmm1
   1400067d3:	f2 0f 2a 4d f8       	cvtsi2sd xmm1,DWORD PTR [rbp-0x8]
   1400067d8:	f2 0f 10 05 c8 4b 00 	movsd  xmm0,QWORD PTR [rip+0x4bc8]        # 14000b3a8 <.rdata+0x38>
   1400067df:	00 
   1400067e0:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400067e4:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   1400067e8:	83 c0 03             	add    eax,0x3
   1400067eb:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400067ee:	c7 85 b8 00 00 00 00 	mov    DWORD PTR [rbp+0xb8],0x0
   1400067f5:	00 00 00 
   1400067f8:	eb 66                	jmp    140006860 <__gdtoa+0x4d6>
   1400067fa:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006801:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006808:	7f 0a                	jg     140006814 <__gdtoa+0x48a>
   14000680a:	c7 85 b8 00 00 00 01 	mov    DWORD PTR [rbp+0xb8],0x1
   140006811:	00 00 00 
   140006814:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   14000681a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000681d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006820:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006823:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006826:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006829:	eb 35                	jmp    140006860 <__gdtoa+0x4d6>
   14000682b:	c7 45 50 00 00 00 00 	mov    DWORD PTR [rbp+0x50],0x0
   140006832:	8b 95 b8 00 00 00    	mov    edx,DWORD PTR [rbp+0xb8]
   140006838:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000683b:	01 d0                	add    eax,edx
   14000683d:	83 c0 01             	add    eax,0x1
   140006840:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006843:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006846:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006849:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000684c:	83 e8 01             	sub    eax,0x1
   14000684f:	89 45 68             	mov    DWORD PTR [rbp+0x68],eax
   140006852:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006855:	85 c0                	test   eax,eax
   140006857:	7f 07                	jg     140006860 <__gdtoa+0x4d6>
   140006859:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006860:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006863:	89 c1                	mov    ecx,eax
   140006865:	e8 56 f6 ff ff       	call   140005ec0 <__rv_alloc_D2A>
   14000686a:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000686e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006872:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006876:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000687d:	7f 09                	jg     140006888 <__gdtoa+0x4fe>
   14000687f:	c7 45 44 00 00 00 00 	mov    DWORD PTR [rbp+0x44],0x0
   140006886:	eb 38                	jmp    1400068c0 <__gdtoa+0x536>
   140006888:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000688f:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140006892:	83 e8 01             	sub    eax,0x1
   140006895:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   140006898:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000689c:	74 22                	je     1400068c0 <__gdtoa+0x536>
   14000689e:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400068a2:	79 07                	jns    1400068ab <__gdtoa+0x521>
   1400068a4:	c7 45 44 02 00 00 00 	mov    DWORD PTR [rbp+0x44],0x2
   1400068ab:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400068ae:	83 e0 08             	and    eax,0x8
   1400068b1:	85 c0                	test   eax,eax
   1400068b3:	74 0b                	je     1400068c0 <__gdtoa+0x536>
   1400068b5:	b8 03 00 00 00       	mov    eax,0x3
   1400068ba:	2b 45 44             	sub    eax,DWORD PTR [rbp+0x44]
   1400068bd:	89 45 44             	mov    DWORD PTR [rbp+0x44],eax
   1400068c0:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   1400068c4:	0f 88 b9 04 00 00    	js     140006d83 <__gdtoa+0x9f9>
   1400068ca:	83 7d 6c 0e          	cmp    DWORD PTR [rbp+0x6c],0xe
   1400068ce:	0f 8f af 04 00 00    	jg     140006d83 <__gdtoa+0x9f9>
   1400068d4:	83 7d 34 00          	cmp    DWORD PTR [rbp+0x34],0x0
   1400068d8:	0f 84 a5 04 00 00    	je     140006d83 <__gdtoa+0x9f9>
   1400068de:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400068e2:	0f 85 9b 04 00 00    	jne    140006d83 <__gdtoa+0x9f9>
   1400068e8:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   1400068ec:	0f 85 91 04 00 00    	jne    140006d83 <__gdtoa+0x9f9>
   1400068f2:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   1400068f9:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   1400068fe:	f2 0f 11 45 e0       	movsd  QWORD PTR [rbp-0x20],xmm0
   140006903:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006906:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140006909:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   14000690c:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   14000690f:	c7 45 70 02 00 00 00 	mov    DWORD PTR [rbp+0x70],0x2
   140006916:	83 7d 58 00          	cmp    DWORD PTR [rbp+0x58],0x0
   14000691a:	0f 8e 98 00 00 00    	jle    1400069b8 <__gdtoa+0x62e>
   140006920:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   140006923:	83 e0 0f             	and    eax,0xf
   140006926:	89 c2                	mov    edx,eax
   140006928:	48 8b 05 71 4d 00 00 	mov    rax,QWORD PTR [rip+0x4d71]        # 14000b6a0 <.refptr.__tens_D2A>
   14000692f:	48 63 d2             	movsxd rdx,edx
   140006932:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006937:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   14000693c:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   14000693f:	c1 f8 04             	sar    eax,0x4
   140006942:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006945:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006948:	83 e0 10             	and    eax,0x10
   14000694b:	85 c0                	test   eax,eax
   14000694d:	74 5e                	je     1400069ad <__gdtoa+0x623>
   14000694f:	83 65 60 0f          	and    DWORD PTR [rbp+0x60],0xf
   140006953:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006958:	48 8b 05 71 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c71]        # 14000b5d0 <.refptr.__bigtens_D2A>
   14000695f:	f2 0f 10 48 20       	movsd  xmm1,QWORD PTR [rax+0x20]
   140006964:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006968:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   14000696d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006971:	eb 3a                	jmp    1400069ad <__gdtoa+0x623>
   140006973:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006976:	83 e0 01             	and    eax,0x1
   140006979:	85 c0                	test   eax,eax
   14000697b:	74 24                	je     1400069a1 <__gdtoa+0x617>
   14000697d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006981:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006984:	48 8b 05 45 4c 00 00 	mov    rax,QWORD PTR [rip+0x4c45]        # 14000b5d0 <.refptr.__bigtens_D2A>
   14000698b:	48 63 d2             	movsxd rdx,edx
   14000698e:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006993:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006998:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   14000699c:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400069a1:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   1400069a4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400069a7:	83 c0 01             	add    eax,0x1
   1400069aa:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400069ad:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400069b1:	75 c0                	jne    140006973 <__gdtoa+0x5e9>
   1400069b3:	e9 8b 00 00 00       	jmp    140006a43 <__gdtoa+0x6b9>
   1400069b8:	f2 0f 10 05 f0 49 00 	movsd  xmm0,QWORD PTR [rip+0x49f0]        # 14000b3b0 <.rdata+0x40>
   1400069bf:	00 
   1400069c0:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   1400069c5:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400069c8:	f7 d8                	neg    eax
   1400069ca:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400069cd:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400069d1:	74 70                	je     140006a43 <__gdtoa+0x6b9>
   1400069d3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   1400069d8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069db:	83 e0 0f             	and    eax,0xf
   1400069de:	89 c2                	mov    edx,eax
   1400069e0:	48 8b 05 b9 4c 00 00 	mov    rax,QWORD PTR [rip+0x4cb9]        # 14000b6a0 <.refptr.__tens_D2A>
   1400069e7:	48 63 d2             	movsxd rdx,edx
   1400069ea:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   1400069ef:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   1400069f3:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   1400069f8:	8b 45 5c             	mov    eax,DWORD PTR [rbp+0x5c]
   1400069fb:	c1 f8 04             	sar    eax,0x4
   1400069fe:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006a01:	eb 3a                	jmp    140006a3d <__gdtoa+0x6b3>
   140006a03:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140006a06:	83 e0 01             	and    eax,0x1
   140006a09:	85 c0                	test   eax,eax
   140006a0b:	74 24                	je     140006a31 <__gdtoa+0x6a7>
   140006a0d:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a11:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a16:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
   140006a19:	48 8b 05 b0 4b 00 00 	mov    rax,QWORD PTR [rip+0x4bb0]        # 14000b5d0 <.refptr.__bigtens_D2A>
   140006a20:	48 63 d2             	movsxd rdx,edx
   140006a23:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006a28:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a2c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a31:	d1 7d 60             	sar    DWORD PTR [rbp+0x60],1
   140006a34:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006a37:	83 c0 01             	add    eax,0x1
   140006a3a:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006a3d:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140006a41:	75 c0                	jne    140006a03 <__gdtoa+0x679>
   140006a43:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   140006a47:	74 47                	je     140006a90 <__gdtoa+0x706>
   140006a49:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a4e:	f2 0f 10 05 5a 49 00 	movsd  xmm0,QWORD PTR [rip+0x495a]        # 14000b3b0 <.rdata+0x40>
   140006a55:	00 
   140006a56:	66 0f 2f c1          	comisd xmm0,xmm1
   140006a5a:	76 34                	jbe    140006a90 <__gdtoa+0x706>
   140006a5c:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006a60:	7e 2e                	jle    140006a90 <__gdtoa+0x706>
   140006a62:	83 7d 68 00          	cmp    DWORD PTR [rbp+0x68],0x0
   140006a66:	0f 8e f5 02 00 00    	jle    140006d61 <__gdtoa+0x9d7>
   140006a6c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   140006a6f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006a72:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140006a76:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006a7b:	f2 0f 10 05 35 49 00 	movsd  xmm0,QWORD PTR [rip+0x4935]        # 14000b3b8 <.rdata+0x48>
   140006a82:	00 
   140006a83:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006a87:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006a8c:	83 45 70 01          	add    DWORD PTR [rbp+0x70],0x1
   140006a90:	66 0f ef c9          	pxor   xmm1,xmm1
   140006a94:	f2 0f 2a 4d 70       	cvtsi2sd xmm1,DWORD PTR [rbp+0x70]
   140006a99:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006a9e:	f2 0f 59 c8          	mulsd  xmm1,xmm0
   140006aa2:	f2 0f 10 05 16 49 00 	movsd  xmm0,QWORD PTR [rip+0x4916]        # 14000b3c0 <.rdata+0x50>
   140006aa9:	00 
   140006aaa:	f2 0f 58 c1          	addsd  xmm0,xmm1
   140006aae:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006ab3:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   140006ab6:	2d 00 00 40 03       	sub    eax,0x3400000
   140006abb:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   140006abe:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ac2:	75 5f                	jne    140006b23 <__gdtoa+0x799>
   140006ac4:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006acb:	00 
   140006acc:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006ad0:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006ad4:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ad9:	f2 0f 10 0d e7 48 00 	movsd  xmm1,QWORD PTR [rip+0x48e7]        # 14000b3c8 <.rdata+0x58>
   140006ae0:	00 
   140006ae1:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ae5:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006aea:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006aef:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006af4:	66 0f 2f c1          	comisd xmm0,xmm1
   140006af8:	0f 87 ac 07 00 00    	ja     1400072aa <__gdtoa+0xf20>
   140006afe:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006b03:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006b08:	f3 0f 7e 15 c0 48 00 	movq   xmm2,QWORD PTR [rip+0x48c0]        # 14000b3d0 <.rdata+0x60>
   140006b0f:	00 
   140006b10:	66 0f 57 c2          	xorpd  xmm0,xmm2
   140006b14:	66 0f 2f c1          	comisd xmm0,xmm1
   140006b18:	0f 87 6e 07 00 00    	ja     14000728c <__gdtoa+0xf02>
   140006b1e:	e9 42 02 00 00       	jmp    140006d65 <__gdtoa+0x9db>
   140006b23:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006b27:	0f 84 22 01 00 00    	je     140006c4f <__gdtoa+0x8c5>
   140006b2d:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006b32:	f2 0f 10 05 a6 48 00 	movsd  xmm0,QWORD PTR [rip+0x48a6]        # 14000b3e0 <.rdata+0x70>
   140006b39:	00 
   140006b3a:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006b3e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006b41:	8d 50 ff             	lea    edx,[rax-0x1]
   140006b44:	48 8b 05 55 4b 00 00 	mov    rax,QWORD PTR [rip+0x4b55]        # 14000b6a0 <.refptr.__tens_D2A>
   140006b4b:	48 63 d2             	movsxd rdx,edx
   140006b4e:	f2 0f 10 0c d0       	movsd  xmm1,QWORD PTR [rax+rdx*8]
   140006b53:	f2 0f 5e c1          	divsd  xmm0,xmm1
   140006b57:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006b5c:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b60:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006b65:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140006b6c:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b71:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006b76:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006b7a:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006b7d:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006b82:	66 0f ef c9          	pxor   xmm1,xmm1
   140006b86:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006b8b:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006b90:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006b94:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006b99:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006b9c:	8d 48 30             	lea    ecx,[rax+0x30]
   140006b9f:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ba3:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006ba7:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006bab:	89 ca                	mov    edx,ecx
   140006bad:	88 10                	mov    BYTE PTR [rax],dl
   140006baf:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006bb4:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006bb9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006bbd:	76 29                	jbe    140006be8 <__gdtoa+0x85e>
   140006bbf:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006bc4:	66 0f ef c9          	pxor   xmm1,xmm1
   140006bc8:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006bcc:	7a 0e                	jp     140006bdc <__gdtoa+0x852>
   140006bce:	66 0f ef c9          	pxor   xmm1,xmm1
   140006bd2:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006bd6:	0f 84 93 0c 00 00    	je     14000786f <__gdtoa+0x14e5>
   140006bdc:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006be3:	e9 87 0c 00 00       	jmp    14000786f <__gdtoa+0x14e5>
   140006be8:	f2 0f 10 55 a8       	movsd  xmm2,QWORD PTR [rbp-0x58]
   140006bed:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006bf2:	66 0f 28 c8          	movapd xmm1,xmm0
   140006bf6:	f2 0f 5c ca          	subsd  xmm1,xmm2
   140006bfa:	f2 0f 10 45 a0       	movsd  xmm0,QWORD PTR [rbp-0x60]
   140006bff:	66 0f 2f c1          	comisd xmm0,xmm1
   140006c03:	0f 87 c3 02 00 00    	ja     140006ecc <__gdtoa+0xb42>
   140006c09:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c0c:	83 c0 01             	add    eax,0x1
   140006c0f:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006c12:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006c15:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006c18:	0f 8e 46 01 00 00    	jle    140006d64 <__gdtoa+0x9da>
   140006c1e:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c23:	f2 0f 10 05 8d 47 00 	movsd  xmm0,QWORD PTR [rip+0x478d]        # 14000b3b8 <.rdata+0x48>
   140006c2a:	00 
   140006c2b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c2f:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c34:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006c39:	f2 0f 10 05 77 47 00 	movsd  xmm0,QWORD PTR [rip+0x4777]        # 14000b3b8 <.rdata+0x48>
   140006c40:	00 
   140006c41:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c45:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006c4a:	e9 1d ff ff ff       	jmp    140006b6c <__gdtoa+0x7e2>
   140006c4f:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006c54:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006c57:	8d 50 ff             	lea    edx,[rax-0x1]
   140006c5a:	48 8b 05 3f 4a 00 00 	mov    rax,QWORD PTR [rip+0x4a3f]        # 14000b6a0 <.refptr.__tens_D2A>
   140006c61:	48 63 d2             	movsxd rdx,edx
   140006c64:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006c69:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006c6d:	f2 0f 11 45 a0       	movsd  QWORD PTR [rbp-0x60],xmm0
   140006c72:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006c79:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c7e:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006c83:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006c87:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006c8a:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
   140006c8e:	74 1c                	je     140006cac <__gdtoa+0x922>
   140006c90:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006c95:	66 0f ef c9          	pxor   xmm1,xmm1
   140006c99:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006c9e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006ca3:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006ca7:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006cac:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006caf:	8d 48 30             	lea    ecx,[rax+0x30]
   140006cb2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006cb6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006cba:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006cbe:	89 ca                	mov    edx,ecx
   140006cc0:	88 10                	mov    BYTE PTR [rax],dl
   140006cc2:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006cc5:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006cc8:	75 73                	jne    140006d3d <__gdtoa+0x9b3>
   140006cca:	f2 0f 10 4d 08       	movsd  xmm1,QWORD PTR [rbp+0x8]
   140006ccf:	f2 0f 10 05 09 47 00 	movsd  xmm0,QWORD PTR [rip+0x4709]        # 14000b3e0 <.rdata+0x70>
   140006cd6:	00 
   140006cd7:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006cdb:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006ce0:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ce5:	f2 0f 10 4d a0       	movsd  xmm1,QWORD PTR [rbp-0x60]
   140006cea:	f2 0f 58 4d 08       	addsd  xmm1,QWORD PTR [rbp+0x8]
   140006cef:	66 0f 2f c1          	comisd xmm0,xmm1
   140006cf3:	0f 87 d6 01 00 00    	ja     140006ecf <__gdtoa+0xb45>
   140006cf9:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006cfe:	f2 0f 10 55 a0       	movsd  xmm2,QWORD PTR [rbp-0x60]
   140006d03:	f2 0f 10 45 08       	movsd  xmm0,QWORD PTR [rbp+0x8]
   140006d08:	f2 0f 5c c2          	subsd  xmm0,xmm2
   140006d0c:	66 0f 2f c1          	comisd xmm0,xmm1
   140006d10:	77 02                	ja     140006d14 <__gdtoa+0x98a>
   140006d12:	eb 51                	jmp    140006d65 <__gdtoa+0x9db>
   140006d14:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006d19:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d1d:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d21:	7a 0e                	jp     140006d31 <__gdtoa+0x9a7>
   140006d23:	66 0f ef c9          	pxor   xmm1,xmm1
   140006d27:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006d2b:	0f 84 41 0b 00 00    	je     140007872 <__gdtoa+0x14e8>
   140006d31:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006d38:	e9 35 0b 00 00       	jmp    140007872 <__gdtoa+0x14e8>
   140006d3d:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006d40:	83 c0 01             	add    eax,0x1
   140006d43:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006d46:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006d4b:	f2 0f 10 05 65 46 00 	movsd  xmm0,QWORD PTR [rip+0x4665]        # 14000b3b8 <.rdata+0x48>
   140006d52:	00 
   140006d53:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006d57:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d5c:	e9 18 ff ff ff       	jmp    140006c79 <__gdtoa+0x8ef>
   140006d61:	90                   	nop
   140006d62:	eb 01                	jmp    140006d65 <__gdtoa+0x9db>
   140006d64:	90                   	nop
   140006d65:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140006d69:	48 89 45 00          	mov    QWORD PTR [rbp+0x0],rax
   140006d6d:	f2 0f 10 45 e0       	movsd  xmm0,QWORD PTR [rbp-0x20]
   140006d72:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006d77:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140006d7a:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   140006d7d:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140006d80:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140006d83:	83 bd 98 00 00 00 00 	cmp    DWORD PTR [rbp+0x98],0x0
   140006d8a:	0f 88 bf 01 00 00    	js     140006f4f <__gdtoa+0xbc5>
   140006d90:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006d97:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140006d9a:	39 45 58             	cmp    DWORD PTR [rbp+0x58],eax
   140006d9d:	0f 8f ac 01 00 00    	jg     140006f4f <__gdtoa+0xbc5>
   140006da3:	48 8b 05 f6 48 00 00 	mov    rax,QWORD PTR [rip+0x48f6]        # 14000b6a0 <.refptr.__tens_D2A>
   140006daa:	8b 55 58             	mov    edx,DWORD PTR [rbp+0x58]
   140006dad:	48 63 d2             	movsxd rdx,edx
   140006db0:	f2 0f 10 04 d0       	movsd  xmm0,QWORD PTR [rax+rdx*8]
   140006db5:	f2 0f 11 45 08       	movsd  QWORD PTR [rbp+0x8],xmm0
   140006dba:	83 bd b8 00 00 00 00 	cmp    DWORD PTR [rbp+0xb8],0x0
   140006dc1:	79 45                	jns    140006e08 <__gdtoa+0xa7e>
   140006dc3:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006dc7:	7f 3f                	jg     140006e08 <__gdtoa+0xa7e>
   140006dc9:	48 c7 45 18 00 00 00 	mov    QWORD PTR [rbp+0x18],0x0
   140006dd0:	00 
   140006dd1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140006dd5:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140006dd9:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006ddd:	0f 88 ac 04 00 00    	js     14000728f <__gdtoa+0xf05>
   140006de3:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006de8:	f2 0f 10 55 08       	movsd  xmm2,QWORD PTR [rbp+0x8]
   140006ded:	f2 0f 10 05 d3 45 00 	movsd  xmm0,QWORD PTR [rip+0x45d3]        # 14000b3c8 <.rdata+0x58>
   140006df4:	00 
   140006df5:	f2 0f 59 c2          	mulsd  xmm0,xmm2
   140006df9:	66 0f 2f c1          	comisd xmm0,xmm1
   140006dfd:	0f 83 8c 04 00 00    	jae    14000728f <__gdtoa+0xf05>
   140006e03:	e9 a6 04 00 00       	jmp    1400072ae <__gdtoa+0xf24>
   140006e08:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   140006e0f:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e14:	f2 0f 5e 45 08       	divsd  xmm0,QWORD PTR [rbp+0x8]
   140006e19:	f2 0f 2c c0          	cvttsd2si eax,xmm0
   140006e1d:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140006e20:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e25:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e29:	f2 0f 2a 4d d4       	cvtsi2sd xmm1,DWORD PTR [rbp-0x2c]
   140006e2e:	f2 0f 59 4d 08       	mulsd  xmm1,QWORD PTR [rbp+0x8]
   140006e33:	f2 0f 5c c1          	subsd  xmm0,xmm1
   140006e37:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006e3c:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006e3f:	8d 48 30             	lea    ecx,[rax+0x30]
   140006e42:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006e46:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006e4a:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006e4e:	89 ca                	mov    edx,ecx
   140006e50:	88 10                	mov    BYTE PTR [rax],dl
   140006e52:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e57:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e5b:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e5f:	7a 0e                	jp     140006e6f <__gdtoa+0xae5>
   140006e61:	66 0f ef c9          	pxor   xmm1,xmm1
   140006e65:	66 0f 2e c1          	ucomisd xmm0,xmm1
   140006e69:	0f 84 da 00 00 00    	je     140006f49 <__gdtoa+0xbbf>
   140006e6f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006e72:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006e75:	0f 85 aa 00 00 00    	jne    140006f25 <__gdtoa+0xb9b>
   140006e7b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140006e7f:	74 12                	je     140006e93 <__gdtoa+0xb09>
   140006e81:	83 7d 44 01          	cmp    DWORD PTR [rbp+0x44],0x1
   140006e85:	74 4b                	je     140006ed2 <__gdtoa+0xb48>
   140006e87:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006e8e:	e9 e3 09 00 00       	jmp    140007876 <__gdtoa+0x14ec>
   140006e93:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006e98:	f2 0f 58 c0          	addsd  xmm0,xmm0
   140006e9c:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006ea1:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006ea6:	66 0f 2f 45 08       	comisd xmm0,QWORD PTR [rbp+0x8]
   140006eab:	77 28                	ja     140006ed5 <__gdtoa+0xb4b>
   140006ead:	f2 0f 10 45 a8       	movsd  xmm0,QWORD PTR [rbp-0x58]
   140006eb2:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006eb7:	7a 63                	jp     140006f1c <__gdtoa+0xb92>
   140006eb9:	66 0f 2e 45 08       	ucomisd xmm0,QWORD PTR [rbp+0x8]
   140006ebe:	75 5c                	jne    140006f1c <__gdtoa+0xb92>
   140006ec0:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140006ec3:	83 e0 01             	and    eax,0x1
   140006ec6:	85 c0                	test   eax,eax
   140006ec8:	74 52                	je     140006f1c <__gdtoa+0xb92>
   140006eca:	eb 0a                	jmp    140006ed6 <__gdtoa+0xb4c>
   140006ecc:	90                   	nop
   140006ecd:	eb 07                	jmp    140006ed6 <__gdtoa+0xb4c>
   140006ecf:	90                   	nop
   140006ed0:	eb 04                	jmp    140006ed6 <__gdtoa+0xb4c>
   140006ed2:	90                   	nop
   140006ed3:	eb 01                	jmp    140006ed6 <__gdtoa+0xb4c>
   140006ed5:	90                   	nop
   140006ed6:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140006edd:	eb 17                	jmp    140006ef6 <__gdtoa+0xb6c>
   140006edf:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ee3:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140006ee7:	75 0d                	jne    140006ef6 <__gdtoa+0xb6c>
   140006ee9:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   140006eed:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006ef1:	c6 00 30             	mov    BYTE PTR [rax],0x30
   140006ef4:	eb 10                	jmp    140006f06 <__gdtoa+0xb7c>
   140006ef6:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   140006efb:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006eff:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140006f02:	3c 39                	cmp    al,0x39
   140006f04:	74 d9                	je     140006edf <__gdtoa+0xb55>
   140006f06:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140006f0a:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140006f0e:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140006f12:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140006f15:	83 c2 01             	add    edx,0x1
   140006f18:	88 10                	mov    BYTE PTR [rax],dl
   140006f1a:	eb 2e                	jmp    140006f4a <__gdtoa+0xbc0>
   140006f1c:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   140006f23:	eb 25                	jmp    140006f4a <__gdtoa+0xbc0>
   140006f25:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f28:	83 c0 01             	add    eax,0x1
   140006f2b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006f2e:	f2 0f 10 4d a8       	movsd  xmm1,QWORD PTR [rbp-0x58]
   140006f33:	f2 0f 10 05 7d 44 00 	movsd  xmm0,QWORD PTR [rip+0x447d]        # 14000b3b8 <.rdata+0x48>
   140006f3a:	00 
   140006f3b:	f2 0f 59 c1          	mulsd  xmm0,xmm1
   140006f3f:	f2 0f 11 45 a8       	movsd  QWORD PTR [rbp-0x58],xmm0
   140006f44:	e9 c6 fe ff ff       	jmp    140006e0f <__gdtoa+0xa85>
   140006f49:	90                   	nop
   140006f4a:	e9 27 09 00 00       	jmp    140007876 <__gdtoa+0x14ec>
   140006f4f:	8b 45 7c             	mov    eax,DWORD PTR [rbp+0x7c]
   140006f52:	89 45 4c             	mov    DWORD PTR [rbp+0x4c],eax
   140006f55:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   140006f58:	89 45 48             	mov    DWORD PTR [rbp+0x48],eax
   140006f5b:	48 c7 45 20 00 00 00 	mov    QWORD PTR [rbp+0x20],0x0
   140006f62:	00 
   140006f63:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140006f67:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140006f6b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   140006f6f:	0f 84 e0 00 00 00    	je     140007055 <__gdtoa+0xccb>
   140006f75:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   140006f78:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   140006f7b:	29 c2                	sub    edx,eax
   140006f7d:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f80:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006f83:	8d 50 01             	lea    edx,[rax+0x1]
   140006f86:	89 55 b0             	mov    DWORD PTR [rbp-0x50],edx
   140006f89:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006f8f:	29 c2                	sub    edx,eax
   140006f91:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006f98:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006f9b:	39 c2                	cmp    edx,eax
   140006f9d:	7d 43                	jge    140006fe2 <__gdtoa+0xc58>
   140006f9f:	83 bd b0 00 00 00 03 	cmp    DWORD PTR [rbp+0xb0],0x3
   140006fa6:	74 3a                	je     140006fe2 <__gdtoa+0xc58>
   140006fa8:	83 bd b0 00 00 00 05 	cmp    DWORD PTR [rbp+0xb0],0x5
   140006faf:	74 31                	je     140006fe2 <__gdtoa+0xc58>
   140006fb1:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   140006fb8:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   140006fbb:	8b 95 98 00 00 00    	mov    edx,DWORD PTR [rbp+0x98]
   140006fc1:	29 c2                	sub    edx,eax
   140006fc3:	8d 42 01             	lea    eax,[rdx+0x1]
   140006fc6:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140006fc9:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006fd0:	7e 68                	jle    14000703a <__gdtoa+0xcb0>
   140006fd2:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140006fd6:	7e 62                	jle    14000703a <__gdtoa+0xcb0>
   140006fd8:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140006fdb:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140006fde:	7d 5a                	jge    14000703a <__gdtoa+0xcb0>
   140006fe0:	eb 0a                	jmp    140006fec <__gdtoa+0xc62>
   140006fe2:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   140006fe9:	7e 50                	jle    14000703b <__gdtoa+0xcb1>
   140006feb:	90                   	nop
   140006fec:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140006fef:	83 e8 01             	sub    eax,0x1
   140006ff2:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140006ff5:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140006ff8:	3b 45 60             	cmp    eax,DWORD PTR [rbp+0x60]
   140006ffb:	7c 08                	jl     140007005 <__gdtoa+0xc7b>
   140006ffd:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140007000:	29 45 48             	sub    DWORD PTR [rbp+0x48],eax
   140007003:	eb 19                	jmp    14000701e <__gdtoa+0xc94>
   140007005:	8b 45 48             	mov    eax,DWORD PTR [rbp+0x48]
   140007008:	29 45 60             	sub    DWORD PTR [rbp+0x60],eax
   14000700b:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   14000700e:	01 45 3c             	add    DWORD PTR [rbp+0x3c],eax
   140007011:	8b 45 60             	mov    eax,DWORD PTR [rbp+0x60]
   140007014:	01 45 78             	add    DWORD PTR [rbp+0x78],eax
   140007017:	c7 45 48 00 00 00 00 	mov    DWORD PTR [rbp+0x48],0x0
   14000701e:	8b 45 6c             	mov    eax,DWORD PTR [rbp+0x6c]
   140007021:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007024:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007027:	85 c0                	test   eax,eax
   140007029:	79 10                	jns    14000703b <__gdtoa+0xcb1>
   14000702b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000702e:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   140007031:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
   140007038:	eb 01                	jmp    14000703b <__gdtoa+0xcb1>
   14000703a:	90                   	nop
   14000703b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000703e:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   140007041:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007044:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   140007047:	b9 01 00 00 00       	mov    ecx,0x1
   14000704c:	e8 f6 0f 00 00       	call   140008047 <__i2b_D2A>
   140007051:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007055:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   140007059:	7e 26                	jle    140007081 <__gdtoa+0xcf7>
   14000705b:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   14000705f:	7e 20                	jle    140007081 <__gdtoa+0xcf7>
   140007061:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   140007064:	8b 45 4c             	mov    eax,DWORD PTR [rbp+0x4c]
   140007067:	39 c2                	cmp    edx,eax
   140007069:	0f 4e c2             	cmovle eax,edx
   14000706c:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000706f:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007072:	29 45 7c             	sub    DWORD PTR [rbp+0x7c],eax
   140007075:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007078:	29 45 4c             	sub    DWORD PTR [rbp+0x4c],eax
   14000707b:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000707e:	29 45 40             	sub    DWORD PTR [rbp+0x40],eax
   140007081:	83 7d 78 00          	cmp    DWORD PTR [rbp+0x78],0x0
   140007085:	7e 7e                	jle    140007105 <__gdtoa+0xd7b>
   140007087:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000708b:	74 65                	je     1400070f2 <__gdtoa+0xd68>
   14000708d:	83 7d 48 00          	cmp    DWORD PTR [rbp+0x48],0x0
   140007091:	7e 3b                	jle    1400070ce <__gdtoa+0xd44>
   140007093:	8b 55 48             	mov    edx,DWORD PTR [rbp+0x48]
   140007096:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000709a:	48 89 c1             	mov    rcx,rax
   14000709d:	e8 11 12 00 00       	call   1400082b3 <__pow5mult_D2A>
   1400070a2:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400070a6:	48 8b 55 28          	mov    rdx,QWORD PTR [rbp+0x28]
   1400070aa:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400070ae:	48 89 c1             	mov    rcx,rax
   1400070b1:	e8 d7 0f 00 00       	call   14000808d <__mult_D2A>
   1400070b6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400070ba:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070be:	48 89 c1             	mov    rcx,rax
   1400070c1:	e8 c8 0d 00 00       	call   140007e8e <__Bfree_D2A>
   1400070c6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400070ca:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070ce:	8b 45 78             	mov    eax,DWORD PTR [rbp+0x78]
   1400070d1:	2b 45 48             	sub    eax,DWORD PTR [rbp+0x48]
   1400070d4:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   1400070d7:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400070db:	74 28                	je     140007105 <__gdtoa+0xd7b>
   1400070dd:	8b 55 60             	mov    edx,DWORD PTR [rbp+0x60]
   1400070e0:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070e4:	48 89 c1             	mov    rcx,rax
   1400070e7:	e8 c7 11 00 00       	call   1400082b3 <__pow5mult_D2A>
   1400070ec:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400070f0:	eb 13                	jmp    140007105 <__gdtoa+0xd7b>
   1400070f2:	8b 55 78             	mov    edx,DWORD PTR [rbp+0x78]
   1400070f5:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400070f9:	48 89 c1             	mov    rcx,rax
   1400070fc:	e8 b2 11 00 00       	call   1400082b3 <__pow5mult_D2A>
   140007101:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007105:	b9 01 00 00 00       	mov    ecx,0x1
   14000710a:	e8 38 0f 00 00       	call   140008047 <__i2b_D2A>
   14000710f:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007113:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007117:	7e 13                	jle    14000712c <__gdtoa+0xda2>
   140007119:	8b 55 3c             	mov    edx,DWORD PTR [rbp+0x3c]
   14000711c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007120:	48 89 c1             	mov    rcx,rax
   140007123:	e8 8b 11 00 00       	call   1400082b3 <__pow5mult_D2A>
   140007128:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000712c:	c7 45 38 00 00 00 00 	mov    DWORD PTR [rbp+0x38],0x0
   140007133:	83 bd b0 00 00 00 01 	cmp    DWORD PTR [rbp+0xb0],0x1
   14000713a:	7f 29                	jg     140007165 <__gdtoa+0xddb>
   14000713c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
   14000713f:	83 f8 01             	cmp    eax,0x1
   140007142:	75 21                	jne    140007165 <__gdtoa+0xddb>
   140007144:	48 8b 85 90 00 00 00 	mov    rax,QWORD PTR [rbp+0x90]
   14000714b:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
   14000714e:	83 c0 01             	add    eax,0x1
   140007151:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
   140007154:	7e 0f                	jle    140007165 <__gdtoa+0xddb>
   140007156:	83 45 7c 01          	add    DWORD PTR [rbp+0x7c],0x1
   14000715a:	83 45 40 01          	add    DWORD PTR [rbp+0x40],0x1
   14000715e:	c7 45 38 01 00 00 00 	mov    DWORD PTR [rbp+0x38],0x1
   140007165:	83 7d 3c 00          	cmp    DWORD PTR [rbp+0x3c],0x0
   140007169:	74 22                	je     14000718d <__gdtoa+0xe03>
   14000716b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000716f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007172:	8d 50 ff             	lea    edx,[rax-0x1]
   140007175:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007179:	48 63 d2             	movsxd rdx,edx
   14000717c:	48 83 c2 04          	add    rdx,0x4
   140007180:	8b 44 90 08          	mov    eax,DWORD PTR [rax+rdx*4+0x8]
   140007184:	89 c1                	mov    ecx,eax
   140007186:	e8 c5 f0 ff ff       	call   140006250 <__hi0bits_D2A>
   14000718b:	eb 05                	jmp    140007192 <__gdtoa+0xe08>
   14000718d:	b8 1f 00 00 00       	mov    eax,0x1f
   140007192:	2b 45 40             	sub    eax,DWORD PTR [rbp+0x40]
   140007195:	83 e8 04             	sub    eax,0x4
   140007198:	83 e0 1f             	and    eax,0x1f
   14000719b:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   14000719e:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400071a1:	01 45 4c             	add    DWORD PTR [rbp+0x4c],eax
   1400071a4:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400071a7:	01 45 7c             	add    DWORD PTR [rbp+0x7c],eax
   1400071aa:	83 7d 7c 00          	cmp    DWORD PTR [rbp+0x7c],0x0
   1400071ae:	7e 13                	jle    1400071c3 <__gdtoa+0xe39>
   1400071b0:	8b 55 7c             	mov    edx,DWORD PTR [rbp+0x7c]
   1400071b3:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071b7:	48 89 c1             	mov    rcx,rax
   1400071ba:	e8 b1 12 00 00       	call   140008470 <__lshift_D2A>
   1400071bf:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   1400071c3:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400071c6:	01 45 40             	add    DWORD PTR [rbp+0x40],eax
   1400071c9:	83 7d 40 00          	cmp    DWORD PTR [rbp+0x40],0x0
   1400071cd:	7e 13                	jle    1400071e2 <__gdtoa+0xe58>
   1400071cf:	8b 55 40             	mov    edx,DWORD PTR [rbp+0x40]
   1400071d2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400071d6:	48 89 c1             	mov    rcx,rax
   1400071d9:	e8 92 12 00 00       	call   140008470 <__lshift_D2A>
   1400071de:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400071e2:	83 7d 54 00          	cmp    DWORD PTR [rbp+0x54],0x0
   1400071e6:	74 5a                	je     140007242 <__gdtoa+0xeb8>
   1400071e8:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400071ec:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400071f0:	48 89 c1             	mov    rcx,rax
   1400071f3:	e8 05 14 00 00       	call   1400085fd <__cmp_D2A>
   1400071f8:	85 c0                	test   eax,eax
   1400071fa:	79 46                	jns    140007242 <__gdtoa+0xeb8>
   1400071fc:	83 6d 58 01          	sub    DWORD PTR [rbp+0x58],0x1
   140007200:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007204:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000720a:	ba 0a 00 00 00       	mov    edx,0xa
   14000720f:	48 89 c1             	mov    rcx,rax
   140007212:	e8 02 0d 00 00       	call   140007f19 <__multadd_D2A>
   140007217:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000721b:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   14000721f:	74 1b                	je     14000723c <__gdtoa+0xeb2>
   140007221:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007225:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000722b:	ba 0a 00 00 00       	mov    edx,0xa
   140007230:	48 89 c1             	mov    rcx,rax
   140007233:	e8 e1 0c 00 00       	call   140007f19 <__multadd_D2A>
   140007238:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000723c:	8b 45 68             	mov    eax,DWORD PTR [rbp+0x68]
   14000723f:	89 45 6c             	mov    DWORD PTR [rbp+0x6c],eax
   140007242:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007246:	0f 8f 81 00 00 00    	jg     1400072cd <__gdtoa+0xf43>
   14000724c:	83 bd b0 00 00 00 02 	cmp    DWORD PTR [rbp+0xb0],0x2
   140007253:	7e 78                	jle    1400072cd <__gdtoa+0xf43>
   140007255:	83 7d 6c 00          	cmp    DWORD PTR [rbp+0x6c],0x0
   140007259:	78 37                	js     140007292 <__gdtoa+0xf08>
   14000725b:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000725f:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007265:	ba 05 00 00 00       	mov    edx,0x5
   14000726a:	48 89 c1             	mov    rcx,rax
   14000726d:	e8 a7 0c 00 00       	call   140007f19 <__multadd_D2A>
   140007272:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140007276:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   14000727a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000727e:	48 89 c1             	mov    rcx,rax
   140007281:	e8 77 13 00 00       	call   1400085fd <__cmp_D2A>
   140007286:	85 c0                	test   eax,eax
   140007288:	7f 23                	jg     1400072ad <__gdtoa+0xf23>
   14000728a:	eb 07                	jmp    140007293 <__gdtoa+0xf09>
   14000728c:	90                   	nop
   14000728d:	eb 04                	jmp    140007293 <__gdtoa+0xf09>
   14000728f:	90                   	nop
   140007290:	eb 01                	jmp    140007293 <__gdtoa+0xf09>
   140007292:	90                   	nop
   140007293:	8b 85 b8 00 00 00    	mov    eax,DWORD PTR [rbp+0xb8]
   140007299:	f7 d0                	not    eax
   14000729b:	89 45 58             	mov    DWORD PTR [rbp+0x58],eax
   14000729e:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400072a5:	e9 87 05 00 00       	jmp    140007831 <__gdtoa+0x14a7>
   1400072aa:	90                   	nop
   1400072ab:	eb 01                	jmp    1400072ae <__gdtoa+0xf24>
   1400072ad:	90                   	nop
   1400072ae:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400072b5:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400072b9:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400072bd:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400072c1:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400072c4:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400072c8:	e9 64 05 00 00       	jmp    140007831 <__gdtoa+0x14a7>
   1400072cd:	83 7d 50 00          	cmp    DWORD PTR [rbp+0x50],0x0
   1400072d1:	0f 84 14 04 00 00    	je     1400076eb <__gdtoa+0x1361>
   1400072d7:	83 7d 4c 00          	cmp    DWORD PTR [rbp+0x4c],0x0
   1400072db:	7e 13                	jle    1400072f0 <__gdtoa+0xf66>
   1400072dd:	8b 55 4c             	mov    edx,DWORD PTR [rbp+0x4c]
   1400072e0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072e4:	48 89 c1             	mov    rcx,rax
   1400072e7:	e8 84 11 00 00       	call   140008470 <__lshift_D2A>
   1400072ec:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400072f0:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400072f4:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400072f8:	83 7d 38 00          	cmp    DWORD PTR [rbp+0x38],0x0
   1400072fc:	74 57                	je     140007355 <__gdtoa+0xfcb>
   1400072fe:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007302:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007305:	89 c1                	mov    ecx,eax
   140007307:	e8 41 0a 00 00       	call   140007d4d <__Balloc_D2A>
   14000730c:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007310:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007314:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007317:	48 98                	cdqe
   140007319:	48 83 c0 02          	add    rax,0x2
   14000731d:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007324:	00 
   140007325:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007329:	48 8d 50 10          	lea    rdx,[rax+0x10]
   14000732d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007331:	48 83 c0 10          	add    rax,0x10
   140007335:	49 89 c8             	mov    r8,rcx
   140007338:	48 89 c1             	mov    rcx,rax
   14000733b:	e8 e8 23 00 00       	call   140009728 <memcpy>
   140007340:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007344:	ba 01 00 00 00       	mov    edx,0x1
   140007349:	48 89 c1             	mov    rcx,rax
   14000734c:	e8 1f 11 00 00       	call   140008470 <__lshift_D2A>
   140007351:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140007355:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   14000735c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007360:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007364:	48 89 c1             	mov    rcx,rax
   140007367:	e8 62 ec ff ff       	call   140005fce <__quorem_D2A>
   14000736c:	83 c0 30             	add    eax,0x30
   14000736f:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007372:	48 8b 55 20          	mov    rdx,QWORD PTR [rbp+0x20]
   140007376:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000737a:	48 89 c1             	mov    rcx,rax
   14000737d:	e8 7b 12 00 00       	call   1400085fd <__cmp_D2A>
   140007382:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   140007385:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007389:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000738d:	48 89 c1             	mov    rcx,rax
   140007390:	e8 38 13 00 00       	call   1400086cd <__diff_D2A>
   140007395:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
   140007399:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   14000739d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
   1400073a0:	85 c0                	test   eax,eax
   1400073a2:	75 15                	jne    1400073b9 <__gdtoa+0x102f>
   1400073a4:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
   1400073a8:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400073ac:	48 89 c1             	mov    rcx,rax
   1400073af:	e8 49 12 00 00       	call   1400085fd <__cmp_D2A>
   1400073b4:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   1400073b7:	eb 07                	jmp    1400073c0 <__gdtoa+0x1036>
   1400073b9:	c7 45 5c 01 00 00 00 	mov    DWORD PTR [rbp+0x5c],0x1
   1400073c0:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
   1400073c4:	48 89 c1             	mov    rcx,rax
   1400073c7:	e8 c2 0a 00 00       	call   140007e8e <__Bfree_D2A>
   1400073cc:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400073d0:	75 70                	jne    140007442 <__gdtoa+0x10b8>
   1400073d2:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   1400073d9:	75 67                	jne    140007442 <__gdtoa+0x10b8>
   1400073db:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   1400073e2:	8b 00                	mov    eax,DWORD PTR [rax]
   1400073e4:	83 e0 01             	and    eax,0x1
   1400073e7:	85 c0                	test   eax,eax
   1400073e9:	75 57                	jne    140007442 <__gdtoa+0x10b8>
   1400073eb:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   1400073ef:	75 51                	jne    140007442 <__gdtoa+0x10b8>
   1400073f1:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400073f5:	0f 84 01 02 00 00    	je     1400075fc <__gdtoa+0x1272>
   1400073fb:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400073ff:	7f 20                	jg     140007421 <__gdtoa+0x1097>
   140007401:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007405:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007408:	83 f8 01             	cmp    eax,0x1
   14000740b:	7f 0b                	jg     140007418 <__gdtoa+0x108e>
   14000740d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007411:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007414:	85 c0                	test   eax,eax
   140007416:	74 14                	je     14000742c <__gdtoa+0x10a2>
   140007418:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000741f:	eb 0b                	jmp    14000742c <__gdtoa+0x10a2>
   140007421:	83 45 74 01          	add    DWORD PTR [rbp+0x74],0x1
   140007425:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   14000742c:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007430:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007434:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007438:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000743b:	88 10                	mov    BYTE PTR [rax],dl
   14000743d:	e9 ef 03 00 00       	jmp    140007831 <__gdtoa+0x14a7>
   140007442:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   140007446:	78 2b                	js     140007473 <__gdtoa+0x10e9>
   140007448:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   14000744c:	0f 85 96 01 00 00    	jne    1400075e8 <__gdtoa+0x125e>
   140007452:	83 bd b0 00 00 00 00 	cmp    DWORD PTR [rbp+0xb0],0x0
   140007459:	0f 85 89 01 00 00    	jne    1400075e8 <__gdtoa+0x125e>
   14000745f:	48 8b 85 a0 00 00 00 	mov    rax,QWORD PTR [rbp+0xa0]
   140007466:	8b 00                	mov    eax,DWORD PTR [rax]
   140007468:	83 e0 01             	and    eax,0x1
   14000746b:	85 c0                	test   eax,eax
   14000746d:	0f 85 75 01 00 00    	jne    1400075e8 <__gdtoa+0x125e>
   140007473:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   140007477:	0f 84 db 00 00 00    	je     140007558 <__gdtoa+0x11ce>
   14000747d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007481:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007484:	83 f8 01             	cmp    eax,0x1
   140007487:	7f 0f                	jg     140007498 <__gdtoa+0x110e>
   140007489:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000748d:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007490:	85 c0                	test   eax,eax
   140007492:	0f 84 c0 00 00 00    	je     140007558 <__gdtoa+0x11ce>
   140007498:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   14000749c:	0f 85 83 00 00 00    	jne    140007525 <__gdtoa+0x119b>
   1400074a2:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400074a9:	e9 24 01 00 00       	jmp    1400075d2 <__gdtoa+0x1248>
   1400074ae:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400074b2:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400074b6:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400074ba:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400074bd:	88 10                	mov    BYTE PTR [rax],dl
   1400074bf:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400074c3:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400074c9:	ba 0a 00 00 00       	mov    edx,0xa
   1400074ce:	48 89 c1             	mov    rcx,rax
   1400074d1:	e8 43 0a 00 00       	call   140007f19 <__multadd_D2A>
   1400074d6:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400074da:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400074de:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   1400074e2:	75 08                	jne    1400074ec <__gdtoa+0x1162>
   1400074e4:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074e8:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400074ec:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400074f0:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400074f4:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400074f8:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400074fe:	ba 0a 00 00 00       	mov    edx,0xa
   140007503:	48 89 c1             	mov    rcx,rax
   140007506:	e8 0e 0a 00 00       	call   140007f19 <__multadd_D2A>
   14000750b:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000750f:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007513:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007517:	48 89 c1             	mov    rcx,rax
   14000751a:	e8 af ea ff ff       	call   140005fce <__quorem_D2A>
   14000751f:	83 c0 30             	add    eax,0x30
   140007522:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007525:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140007529:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000752d:	48 89 c1             	mov    rcx,rax
   140007530:	e8 c8 10 00 00       	call   1400085fd <__cmp_D2A>
   140007535:	85 c0                	test   eax,eax
   140007537:	0f 8f 71 ff ff ff    	jg     1400074ae <__gdtoa+0x1124>
   14000753d:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007540:	8d 50 01             	lea    edx,[rax+0x1]
   140007543:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   140007546:	83 f8 39             	cmp    eax,0x39
   140007549:	0f 84 b0 00 00 00    	je     1400075ff <__gdtoa+0x1275>
   14000754f:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007556:	eb 7a                	jmp    1400075d2 <__gdtoa+0x1248>
   140007558:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000755c:	7e 53                	jle    1400075b1 <__gdtoa+0x1227>
   14000755e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007562:	ba 01 00 00 00       	mov    edx,0x1
   140007567:	48 89 c1             	mov    rcx,rax
   14000756a:	e8 01 0f 00 00       	call   140008470 <__lshift_D2A>
   14000756f:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007573:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007577:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000757b:	48 89 c1             	mov    rcx,rax
   14000757e:	e8 7a 10 00 00       	call   1400085fd <__cmp_D2A>
   140007583:	89 45 5c             	mov    DWORD PTR [rbp+0x5c],eax
   140007586:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   14000758a:	7f 10                	jg     14000759c <__gdtoa+0x1212>
   14000758c:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   140007590:	75 18                	jne    1400075aa <__gdtoa+0x1220>
   140007592:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007595:	83 e0 01             	and    eax,0x1
   140007598:	85 c0                	test   eax,eax
   14000759a:	74 0e                	je     1400075aa <__gdtoa+0x1220>
   14000759c:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   14000759f:	8d 50 01             	lea    edx,[rax+0x1]
   1400075a2:	89 55 74             	mov    DWORD PTR [rbp+0x74],edx
   1400075a5:	83 f8 39             	cmp    eax,0x39
   1400075a8:	74 58                	je     140007602 <__gdtoa+0x1278>
   1400075aa:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400075b1:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075b5:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400075b8:	83 f8 01             	cmp    eax,0x1
   1400075bb:	7f 0b                	jg     1400075c8 <__gdtoa+0x123e>
   1400075bd:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400075c1:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   1400075c4:	85 c0                	test   eax,eax
   1400075c6:	74 09                	je     1400075d1 <__gdtoa+0x1247>
   1400075c8:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   1400075cf:	eb 01                	jmp    1400075d2 <__gdtoa+0x1248>
   1400075d1:	90                   	nop
   1400075d2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400075d6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400075da:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400075de:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   1400075e1:	88 10                	mov    BYTE PTR [rax],dl
   1400075e3:	e9 49 02 00 00       	jmp    140007831 <__gdtoa+0x14a7>
   1400075e8:	83 7d 5c 00          	cmp    DWORD PTR [rbp+0x5c],0x0
   1400075ec:	7e 52                	jle    140007640 <__gdtoa+0x12b6>
   1400075ee:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   1400075f2:	74 4c                	je     140007640 <__gdtoa+0x12b6>
   1400075f4:	83 7d 74 39          	cmp    DWORD PTR [rbp+0x74],0x39
   1400075f8:	75 24                	jne    14000761e <__gdtoa+0x1294>
   1400075fa:	eb 07                	jmp    140007603 <__gdtoa+0x1279>
   1400075fc:	90                   	nop
   1400075fd:	eb 04                	jmp    140007603 <__gdtoa+0x1279>
   1400075ff:	90                   	nop
   140007600:	eb 01                	jmp    140007603 <__gdtoa+0x1279>
   140007602:	90                   	nop
   140007603:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007607:	48 8d 50 01          	lea    rdx,[rax+0x1]
   14000760b:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000760f:	c6 00 39             	mov    BYTE PTR [rax],0x39
   140007612:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007619:	e9 9d 01 00 00       	jmp    1400077bb <__gdtoa+0x1431>
   14000761e:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   140007625:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   140007628:	8d 48 01             	lea    ecx,[rax+0x1]
   14000762b:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000762f:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007633:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007637:	89 ca                	mov    edx,ecx
   140007639:	88 10                	mov    BYTE PTR [rax],dl
   14000763b:	e9 f1 01 00 00       	jmp    140007831 <__gdtoa+0x14a7>
   140007640:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007644:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007648:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   14000764c:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   14000764f:	88 10                	mov    BYTE PTR [rax],dl
   140007651:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   140007654:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   140007657:	0f 84 ea 00 00 00    	je     140007747 <__gdtoa+0x13bd>
   14000765d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007661:	41 b8 00 00 00 00    	mov    r8d,0x0
   140007667:	ba 0a 00 00 00       	mov    edx,0xa
   14000766c:	48 89 c1             	mov    rcx,rax
   14000766f:	e8 a5 08 00 00       	call   140007f19 <__multadd_D2A>
   140007674:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   140007678:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000767c:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007680:	75 25                	jne    1400076a7 <__gdtoa+0x131d>
   140007682:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007686:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000768c:	ba 0a 00 00 00       	mov    edx,0xa
   140007691:	48 89 c1             	mov    rcx,rax
   140007694:	e8 80 08 00 00       	call   140007f19 <__multadd_D2A>
   140007699:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   14000769d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400076a1:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400076a5:	eb 36                	jmp    1400076dd <__gdtoa+0x1353>
   1400076a7:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400076ab:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076b1:	ba 0a 00 00 00       	mov    edx,0xa
   1400076b6:	48 89 c1             	mov    rcx,rax
   1400076b9:	e8 5b 08 00 00       	call   140007f19 <__multadd_D2A>
   1400076be:	48 89 45 20          	mov    QWORD PTR [rbp+0x20],rax
   1400076c2:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400076c6:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400076cc:	ba 0a 00 00 00       	mov    edx,0xa
   1400076d1:	48 89 c1             	mov    rcx,rax
   1400076d4:	e8 40 08 00 00       	call   140007f19 <__multadd_D2A>
   1400076d9:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400076dd:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   1400076e0:	83 c0 01             	add    eax,0x1
   1400076e3:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   1400076e6:	e9 71 fc ff ff       	jmp    14000735c <__gdtoa+0xfd2>
   1400076eb:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
   1400076f2:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   1400076f6:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400076fa:	48 89 c1             	mov    rcx,rax
   1400076fd:	e8 cc e8 ff ff       	call   140005fce <__quorem_D2A>
   140007702:	83 c0 30             	add    eax,0x30
   140007705:	89 45 74             	mov    DWORD PTR [rbp+0x74],eax
   140007708:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000770c:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140007710:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   140007714:	8b 55 74             	mov    edx,DWORD PTR [rbp+0x74]
   140007717:	88 10                	mov    BYTE PTR [rax],dl
   140007719:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000771c:	39 45 6c             	cmp    DWORD PTR [rbp+0x6c],eax
   14000771f:	7e 29                	jle    14000774a <__gdtoa+0x13c0>
   140007721:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007725:	41 b8 00 00 00 00    	mov    r8d,0x0
   14000772b:	ba 0a 00 00 00       	mov    edx,0xa
   140007730:	48 89 c1             	mov    rcx,rax
   140007733:	e8 e1 07 00 00       	call   140007f19 <__multadd_D2A>
   140007738:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000773c:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
   14000773f:	83 c0 01             	add    eax,0x1
   140007742:	89 45 b0             	mov    DWORD PTR [rbp-0x50],eax
   140007745:	eb ab                	jmp    1400076f2 <__gdtoa+0x1368>
   140007747:	90                   	nop
   140007748:	eb 01                	jmp    14000774b <__gdtoa+0x13c1>
   14000774a:	90                   	nop
   14000774b:	83 7d 44 00          	cmp    DWORD PTR [rbp+0x44],0x0
   14000774f:	74 26                	je     140007777 <__gdtoa+0x13ed>
   140007751:	83 7d 44 02          	cmp    DWORD PTR [rbp+0x44],0x2
   140007755:	0f 84 ae 00 00 00    	je     140007809 <__gdtoa+0x147f>
   14000775b:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000775f:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007762:	83 f8 01             	cmp    eax,0x1
   140007765:	7f 50                	jg     1400077b7 <__gdtoa+0x142d>
   140007767:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000776b:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000776e:	85 c0                	test   eax,eax
   140007770:	75 45                	jne    1400077b7 <__gdtoa+0x142d>
   140007772:	e9 92 00 00 00       	jmp    140007809 <__gdtoa+0x147f>
   140007777:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000777b:	ba 01 00 00 00       	mov    edx,0x1
   140007780:	48 89 c1             	mov    rcx,rax
   140007783:	e8 e8 0c 00 00       	call   140008470 <__lshift_D2A>
   140007788:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000778c:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140007790:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007794:	48 89 c1             	mov    rcx,rax
   140007797:	e8 61 0e 00 00       	call   1400085fd <__cmp_D2A>
   14000779c:	89 45 60             	mov    DWORD PTR [rbp+0x60],eax
   14000779f:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400077a3:	7f 15                	jg     1400077ba <__gdtoa+0x1430>
   1400077a5:	83 7d 60 00          	cmp    DWORD PTR [rbp+0x60],0x0
   1400077a9:	75 61                	jne    14000780c <__gdtoa+0x1482>
   1400077ab:	8b 45 74             	mov    eax,DWORD PTR [rbp+0x74]
   1400077ae:	83 e0 01             	and    eax,0x1
   1400077b1:	85 c0                	test   eax,eax
   1400077b3:	74 5a                	je     14000780f <__gdtoa+0x1485>
   1400077b5:	eb 04                	jmp    1400077bb <__gdtoa+0x1431>
   1400077b7:	90                   	nop
   1400077b8:	eb 01                	jmp    1400077bb <__gdtoa+0x1431>
   1400077ba:	90                   	nop
   1400077bb:	c7 45 64 20 00 00 00 	mov    DWORD PTR [rbp+0x64],0x20
   1400077c2:	eb 1f                	jmp    1400077e3 <__gdtoa+0x1459>
   1400077c4:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077c8:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   1400077cc:	75 15                	jne    1400077e3 <__gdtoa+0x1459>
   1400077ce:	83 45 58 01          	add    DWORD PTR [rbp+0x58],0x1
   1400077d2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077d6:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077da:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077de:	c6 00 31             	mov    BYTE PTR [rax],0x31
   1400077e1:	eb 4e                	jmp    140007831 <__gdtoa+0x14a7>
   1400077e3:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   1400077e8:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077ec:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400077ef:	3c 39                	cmp    al,0x39
   1400077f1:	74 d1                	je     1400077c4 <__gdtoa+0x143a>
   1400077f3:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400077f7:	48 8d 50 01          	lea    rdx,[rax+0x1]
   1400077fb:	48 89 55 00          	mov    QWORD PTR [rbp+0x0],rdx
   1400077ff:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140007802:	83 c2 01             	add    edx,0x1
   140007805:	88 10                	mov    BYTE PTR [rax],dl
   140007807:	eb 28                	jmp    140007831 <__gdtoa+0x14a7>
   140007809:	90                   	nop
   14000780a:	eb 04                	jmp    140007810 <__gdtoa+0x1486>
   14000780c:	90                   	nop
   14000780d:	eb 01                	jmp    140007810 <__gdtoa+0x1486>
   14000780f:	90                   	nop
   140007810:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007814:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007817:	83 f8 01             	cmp    eax,0x1
   14000781a:	7f 0b                	jg     140007827 <__gdtoa+0x149d>
   14000781c:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140007820:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140007823:	85 c0                	test   eax,eax
   140007825:	74 09                	je     140007830 <__gdtoa+0x14a6>
   140007827:	c7 45 64 10 00 00 00 	mov    DWORD PTR [rbp+0x64],0x10
   14000782e:	eb 01                	jmp    140007831 <__gdtoa+0x14a7>
   140007830:	90                   	nop
   140007831:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007835:	48 89 c1             	mov    rcx,rax
   140007838:	e8 51 06 00 00       	call   140007e8e <__Bfree_D2A>
   14000783d:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   140007842:	74 31                	je     140007875 <__gdtoa+0x14eb>
   140007844:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140007849:	74 16                	je     140007861 <__gdtoa+0x14d7>
   14000784b:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   14000784f:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140007853:	74 0c                	je     140007861 <__gdtoa+0x14d7>
   140007855:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140007859:	48 89 c1             	mov    rcx,rax
   14000785c:	e8 2d 06 00 00       	call   140007e8e <__Bfree_D2A>
   140007861:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140007865:	48 89 c1             	mov    rcx,rax
   140007868:	e8 21 06 00 00       	call   140007e8e <__Bfree_D2A>
   14000786d:	eb 0e                	jmp    14000787d <__gdtoa+0x14f3>
   14000786f:	90                   	nop
   140007870:	eb 0b                	jmp    14000787d <__gdtoa+0x14f3>
   140007872:	90                   	nop
   140007873:	eb 08                	jmp    14000787d <__gdtoa+0x14f3>
   140007875:	90                   	nop
   140007876:	eb 05                	jmp    14000787d <__gdtoa+0x14f3>
   140007878:	48 83 6d 00 01       	sub    QWORD PTR [rbp+0x0],0x1
   14000787d:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   140007881:	48 39 45 e8          	cmp    QWORD PTR [rbp-0x18],rax
   140007885:	73 0f                	jae    140007896 <__gdtoa+0x150c>
   140007887:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   14000788b:	48 83 e8 01          	sub    rax,0x1
   14000788f:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140007892:	3c 30                	cmp    al,0x30
   140007894:	74 e2                	je     140007878 <__gdtoa+0x14ee>
   140007896:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000789a:	48 89 c1             	mov    rcx,rax
   14000789d:	e8 ec 05 00 00       	call   140007e8e <__Bfree_D2A>
   1400078a2:	48 8b 45 00          	mov    rax,QWORD PTR [rbp+0x0]
   1400078a6:	c6 00 00             	mov    BYTE PTR [rax],0x0
   1400078a9:	8b 45 58             	mov    eax,DWORD PTR [rbp+0x58]
   1400078ac:	8d 50 01             	lea    edx,[rax+0x1]
   1400078af:	48 8b 85 c0 00 00 00 	mov    rax,QWORD PTR [rbp+0xc0]
   1400078b6:	89 10                	mov    DWORD PTR [rax],edx
   1400078b8:	48 83 bd c8 00 00 00 	cmp    QWORD PTR [rbp+0xc8],0x0
   1400078bf:	00 
   1400078c0:	74 0e                	je     1400078d0 <__gdtoa+0x1546>
   1400078c2:	48 8b 85 c8 00 00 00 	mov    rax,QWORD PTR [rbp+0xc8]
   1400078c9:	48 8b 55 00          	mov    rdx,QWORD PTR [rbp+0x0]
   1400078cd:	48 89 10             	mov    QWORD PTR [rax],rdx
   1400078d0:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078d7:	8b 00                	mov    eax,DWORD PTR [rax]
   1400078d9:	0b 45 64             	or     eax,DWORD PTR [rbp+0x64]
   1400078dc:	89 c2                	mov    edx,eax
   1400078de:	48 8b 85 a8 00 00 00 	mov    rax,QWORD PTR [rbp+0xa8]
   1400078e5:	89 10                	mov    DWORD PTR [rax],edx
   1400078e7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400078eb:	48 81 c4 00 01 00 00 	add    rsp,0x100
   1400078f2:	5d                   	pop    rbp
   1400078f3:	c3                   	ret
   1400078f4:	90                   	nop
   1400078f5:	90                   	nop
   1400078f6:	90                   	nop
   1400078f7:	90                   	nop
   1400078f8:	90                   	nop
   1400078f9:	90                   	nop
   1400078fa:	90                   	nop
   1400078fb:	90                   	nop
   1400078fc:	90                   	nop
   1400078fd:	90                   	nop
   1400078fe:	90                   	nop
   1400078ff:	90                   	nop

0000000140007900 <__lo0bits_D2A>:
   140007900:	55                   	push   rbp
   140007901:	48 89 e5             	mov    rbp,rsp
   140007904:	48 83 ec 10          	sub    rsp,0x10
   140007908:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000790c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007910:	8b 00                	mov    eax,DWORD PTR [rax]
   140007912:	f3 0f bc c0          	tzcnt  eax,eax
   140007916:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007919:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000791d:	8b 10                	mov    edx,DWORD PTR [rax]
   14000791f:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007922:	89 c1                	mov    ecx,eax
   140007924:	d3 ea                	shr    edx,cl
   140007926:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000792a:	89 10                	mov    DWORD PTR [rax],edx
   14000792c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000792f:	48 83 c4 10          	add    rsp,0x10
   140007933:	5d                   	pop    rbp
   140007934:	c3                   	ret

0000000140007935 <__rshift_D2A>:
   140007935:	55                   	push   rbp
   140007936:	48 89 e5             	mov    rbp,rsp
   140007939:	48 83 ec 20          	sub    rsp,0x20
   14000793d:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007941:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007944:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007948:	48 83 c0 18          	add    rax,0x18
   14000794c:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007950:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007954:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007958:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000795b:	c1 f8 05             	sar    eax,0x5
   14000795e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140007961:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007965:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007968:	39 45 e8             	cmp    DWORD PTR [rbp-0x18],eax
   14000796b:	0f 8d e4 00 00 00    	jge    140007a55 <__rshift_D2A+0x120>
   140007971:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007975:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007978:	48 98                	cdqe
   14000797a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007981:	00 
   140007982:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007986:	48 01 d0             	add    rax,rdx
   140007989:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   14000798d:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140007990:	48 98                	cdqe
   140007992:	48 c1 e0 02          	shl    rax,0x2
   140007996:	48 01 45 f8          	add    QWORD PTR [rbp-0x8],rax
   14000799a:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000799e:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400079a2:	0f 84 a3 00 00 00    	je     140007a4b <__rshift_D2A+0x116>
   1400079a8:	b8 20 00 00 00       	mov    eax,0x20
   1400079ad:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   1400079b0:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   1400079b3:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079b7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079bb:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400079bf:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079c1:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400079c4:	89 c1                	mov    ecx,eax
   1400079c6:	d3 ea                	shr    edx,cl
   1400079c8:	89 d0                	mov    eax,edx
   1400079ca:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400079cd:	eb 3c                	jmp    140007a0b <__rshift_D2A+0xd6>
   1400079cf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079d3:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079d5:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   1400079d8:	89 c1                	mov    ecx,eax
   1400079da:	d3 e2                	shl    edx,cl
   1400079dc:	89 d1                	mov    ecx,edx
   1400079de:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400079e2:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079e6:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400079ea:	0b 4d ec             	or     ecx,DWORD PTR [rbp-0x14]
   1400079ed:	89 ca                	mov    edx,ecx
   1400079ef:	89 10                	mov    DWORD PTR [rax],edx
   1400079f1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400079f5:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400079f9:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
   1400079fd:	8b 10                	mov    edx,DWORD PTR [rax]
   1400079ff:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007a02:	89 c1                	mov    ecx,eax
   140007a04:	d3 ea                	shr    edx,cl
   140007a06:	89 d0                	mov    eax,edx
   140007a08:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140007a0b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a0f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007a13:	72 ba                	jb     1400079cf <__rshift_D2A+0x9a>
   140007a15:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a19:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007a1c:	89 10                	mov    DWORD PTR [rax],edx
   140007a1e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a22:	8b 00                	mov    eax,DWORD PTR [rax]
   140007a24:	85 c0                	test   eax,eax
   140007a26:	74 2d                	je     140007a55 <__rshift_D2A+0x120>
   140007a28:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140007a2d:	eb 26                	jmp    140007a55 <__rshift_D2A+0x120>
   140007a2f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140007a33:	48 8d 42 04          	lea    rax,[rdx+0x4]
   140007a37:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007a3b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007a3f:	48 8d 48 04          	lea    rcx,[rax+0x4]
   140007a43:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
   140007a47:	8b 12                	mov    edx,DWORD PTR [rdx]
   140007a49:	89 10                	mov    DWORD PTR [rax],edx
   140007a4b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007a4f:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
   140007a53:	72 da                	jb     140007a2f <__rshift_D2A+0xfa>
   140007a55:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a59:	48 83 c0 18          	add    rax,0x18
   140007a5d:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140007a61:	48 29 c2             	sub    rdx,rax
   140007a64:	48 89 d0             	mov    rax,rdx
   140007a67:	48 c1 f8 02          	sar    rax,0x2
   140007a6b:	89 c2                	mov    edx,eax
   140007a6d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a71:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140007a74:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a78:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007a7b:	85 c0                	test   eax,eax
   140007a7d:	75 0b                	jne    140007a8a <__rshift_D2A+0x155>
   140007a7f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007a83:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   140007a8a:	90                   	nop
   140007a8b:	48 83 c4 20          	add    rsp,0x20
   140007a8f:	5d                   	pop    rbp
   140007a90:	c3                   	ret

0000000140007a91 <__trailz_D2A>:
   140007a91:	55                   	push   rbp
   140007a92:	48 89 e5             	mov    rbp,rsp
   140007a95:	48 83 ec 40          	sub    rsp,0x40
   140007a99:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007a9d:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007aa4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007aa8:	48 83 c0 18          	add    rax,0x18
   140007aac:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007ab0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ab4:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007ab7:	48 98                	cdqe
   140007ab9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140007ac0:	00 
   140007ac1:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ac5:	48 01 d0             	add    rax,rdx
   140007ac8:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007acc:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140007ad3:	eb 09                	jmp    140007ade <__trailz_D2A+0x4d>
   140007ad5:	83 45 f4 20          	add    DWORD PTR [rbp-0xc],0x20
   140007ad9:	48 83 45 f8 04       	add    QWORD PTR [rbp-0x8],0x4
   140007ade:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007ae2:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007ae6:	73 0a                	jae    140007af2 <__trailz_D2A+0x61>
   140007ae8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007aec:	8b 00                	mov    eax,DWORD PTR [rax]
   140007aee:	85 c0                	test   eax,eax
   140007af0:	74 e3                	je     140007ad5 <__trailz_D2A+0x44>
   140007af2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007af6:	48 3b 45 e8          	cmp    rax,QWORD PTR [rbp-0x18]
   140007afa:	73 18                	jae    140007b14 <__trailz_D2A+0x83>
   140007afc:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007b00:	8b 00                	mov    eax,DWORD PTR [rax]
   140007b02:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007b05:	48 8d 45 e4          	lea    rax,[rbp-0x1c]
   140007b09:	48 89 c1             	mov    rcx,rax
   140007b0c:	e8 ef fd ff ff       	call   140007900 <__lo0bits_D2A>
   140007b11:	01 45 f4             	add    DWORD PTR [rbp-0xc],eax
   140007b14:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007b17:	48 83 c4 40          	add    rsp,0x40
   140007b1b:	5d                   	pop    rbp
   140007b1c:	c3                   	ret
   140007b1d:	90                   	nop
   140007b1e:	90                   	nop
   140007b1f:	90                   	nop

0000000140007b20 <dtoa_lock_cleanup>:
   140007b20:	55                   	push   rbp
   140007b21:	48 89 e5             	mov    rbp,rsp
   140007b24:	48 83 ec 40          	sub    rsp,0x40
   140007b28:	48 8d 05 c1 76 00 00 	lea    rax,[rip+0x76c1]        # 14000f1f0 <dtoa_CS_init>
   140007b2f:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007b33:	c7 45 ec 03 00 00 00 	mov    DWORD PTR [rbp-0x14],0x3
   140007b3a:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007b3d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007b41:	87 10                	xchg   DWORD PTR [rax],edx
   140007b43:	89 d0                	mov    eax,edx
   140007b45:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007b48:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007b4c:	75 3d                	jne    140007b8b <dtoa_lock_cleanup+0x6b>
   140007b4e:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007b55:	eb 2e                	jmp    140007b85 <dtoa_lock_cleanup+0x65>
   140007b57:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007b5a:	48 63 d0             	movsxd rdx,eax
   140007b5d:	48 89 d0             	mov    rax,rdx
   140007b60:	48 c1 e0 02          	shl    rax,0x2
   140007b64:	48 01 d0             	add    rax,rdx
   140007b67:	48 c1 e0 03          	shl    rax,0x3
   140007b6b:	48 8d 15 2e 76 00 00 	lea    rdx,[rip+0x762e]        # 14000f1a0 <dtoa_CritSec>
   140007b72:	48 01 d0             	add    rax,rdx
   140007b75:	48 89 c1             	mov    rcx,rax
   140007b78:	48 8b 05 79 86 00 00 	mov    rax,QWORD PTR [rip+0x8679]        # 1400101f8 <__IAT_start__>
   140007b7f:	ff d0                	call   rax
   140007b81:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007b85:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007b89:	7e cc                	jle    140007b57 <dtoa_lock_cleanup+0x37>
   140007b8b:	90                   	nop
   140007b8c:	48 83 c4 40          	add    rsp,0x40
   140007b90:	5d                   	pop    rbp
   140007b91:	c3                   	ret

0000000140007b92 <dtoa_lock>:
   140007b92:	55                   	push   rbp
   140007b93:	48 89 e5             	mov    rbp,rsp
   140007b96:	48 83 ec 40          	sub    rsp,0x40
   140007b9a:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007b9d:	8b 05 4d 76 00 00    	mov    eax,DWORD PTR [rip+0x764d]        # 14000f1f0 <dtoa_CS_init>
   140007ba3:	83 f8 02             	cmp    eax,0x2
   140007ba6:	75 2c                	jne    140007bd4 <dtoa_lock+0x42>
   140007ba8:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007bab:	48 89 d0             	mov    rax,rdx
   140007bae:	48 c1 e0 02          	shl    rax,0x2
   140007bb2:	48 01 d0             	add    rax,rdx
   140007bb5:	48 c1 e0 03          	shl    rax,0x3
   140007bb9:	48 8d 15 e0 75 00 00 	lea    rdx,[rip+0x75e0]        # 14000f1a0 <dtoa_CritSec>
   140007bc0:	48 01 d0             	add    rax,rdx
   140007bc3:	48 89 c1             	mov    rcx,rax
   140007bc6:	48 8b 05 33 86 00 00 	mov    rax,QWORD PTR [rip+0x8633]        # 140010200 <__imp_EnterCriticalSection>
   140007bcd:	ff d0                	call   rax
   140007bcf:	e9 ea 00 00 00       	jmp    140007cbe <dtoa_lock+0x12c>
   140007bd4:	8b 05 16 76 00 00    	mov    eax,DWORD PTR [rip+0x7616]        # 14000f1f0 <dtoa_CS_init>
   140007bda:	85 c0                	test   eax,eax
   140007bdc:	0f 85 9e 00 00 00    	jne    140007c80 <dtoa_lock+0xee>
   140007be2:	48 8d 05 07 76 00 00 	lea    rax,[rip+0x7607]        # 14000f1f0 <dtoa_CS_init>
   140007be9:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007bed:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
   140007bf4:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140007bf7:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007bfb:	87 10                	xchg   DWORD PTR [rax],edx
   140007bfd:	89 d0                	mov    eax,edx
   140007bff:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140007c02:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140007c06:	75 58                	jne    140007c60 <dtoa_lock+0xce>
   140007c08:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007c0f:	eb 2e                	jmp    140007c3f <dtoa_lock+0xad>
   140007c11:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007c14:	48 63 d0             	movsxd rdx,eax
   140007c17:	48 89 d0             	mov    rax,rdx
   140007c1a:	48 c1 e0 02          	shl    rax,0x2
   140007c1e:	48 01 d0             	add    rax,rdx
   140007c21:	48 c1 e0 03          	shl    rax,0x3
   140007c25:	48 8d 15 74 75 00 00 	lea    rdx,[rip+0x7574]        # 14000f1a0 <dtoa_CritSec>
   140007c2c:	48 01 d0             	add    rax,rdx
   140007c2f:	48 89 c1             	mov    rcx,rax
   140007c32:	48 8b 05 f7 85 00 00 	mov    rax,QWORD PTR [rip+0x85f7]        # 140010230 <__imp_InitializeCriticalSection>
   140007c39:	ff d0                	call   rax
   140007c3b:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007c3f:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
   140007c43:	7e cc                	jle    140007c11 <dtoa_lock+0x7f>
   140007c45:	48 8d 05 d4 fe ff ff 	lea    rax,[rip+0xfffffffffffffed4]        # 140007b20 <dtoa_lock_cleanup>
   140007c4c:	48 89 c1             	mov    rcx,rax
   140007c4f:	e8 db 99 ff ff       	call   14000162f <atexit>
   140007c54:	c7 05 92 75 00 00 02 	mov    DWORD PTR [rip+0x7592],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c5b:	00 00 00 
   140007c5e:	eb 20                	jmp    140007c80 <dtoa_lock+0xee>
   140007c60:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
   140007c64:	75 1a                	jne    140007c80 <dtoa_lock+0xee>
   140007c66:	c7 05 80 75 00 00 02 	mov    DWORD PTR [rip+0x7580],0x2        # 14000f1f0 <dtoa_CS_init>
   140007c6d:	00 00 00 
   140007c70:	eb 0e                	jmp    140007c80 <dtoa_lock+0xee>
   140007c72:	b9 01 00 00 00       	mov    ecx,0x1
   140007c77:	48 8b 05 da 85 00 00 	mov    rax,QWORD PTR [rip+0x85da]        # 140010258 <__imp_Sleep>
   140007c7e:	ff d0                	call   rax
   140007c80:	8b 05 6a 75 00 00    	mov    eax,DWORD PTR [rip+0x756a]        # 14000f1f0 <dtoa_CS_init>
   140007c86:	83 f8 01             	cmp    eax,0x1
   140007c89:	74 e7                	je     140007c72 <dtoa_lock+0xe0>
   140007c8b:	8b 05 5f 75 00 00    	mov    eax,DWORD PTR [rip+0x755f]        # 14000f1f0 <dtoa_CS_init>
   140007c91:	83 f8 02             	cmp    eax,0x2
   140007c94:	75 28                	jne    140007cbe <dtoa_lock+0x12c>
   140007c96:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007c99:	48 89 d0             	mov    rax,rdx
   140007c9c:	48 c1 e0 02          	shl    rax,0x2
   140007ca0:	48 01 d0             	add    rax,rdx
   140007ca3:	48 c1 e0 03          	shl    rax,0x3
   140007ca7:	48 8d 15 f2 74 00 00 	lea    rdx,[rip+0x74f2]        # 14000f1a0 <dtoa_CritSec>
   140007cae:	48 01 d0             	add    rax,rdx
   140007cb1:	48 89 c1             	mov    rcx,rax
   140007cb4:	48 8b 05 45 85 00 00 	mov    rax,QWORD PTR [rip+0x8545]        # 140010200 <__imp_EnterCriticalSection>
   140007cbb:	ff d0                	call   rax
   140007cbd:	90                   	nop
   140007cbe:	48 83 c4 40          	add    rsp,0x40
   140007cc2:	5d                   	pop    rbp
   140007cc3:	c3                   	ret

0000000140007cc4 <dtoa_unlock>:
   140007cc4:	55                   	push   rbp
   140007cc5:	48 89 e5             	mov    rbp,rsp
   140007cc8:	48 83 ec 20          	sub    rsp,0x20
   140007ccc:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007ccf:	8b 05 1b 75 00 00    	mov    eax,DWORD PTR [rip+0x751b]        # 14000f1f0 <dtoa_CS_init>
   140007cd5:	83 f8 02             	cmp    eax,0x2
   140007cd8:	75 27                	jne    140007d01 <dtoa_unlock+0x3d>
   140007cda:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007cdd:	48 89 d0             	mov    rax,rdx
   140007ce0:	48 c1 e0 02          	shl    rax,0x2
   140007ce4:	48 01 d0             	add    rax,rdx
   140007ce7:	48 c1 e0 03          	shl    rax,0x3
   140007ceb:	48 8d 15 ae 74 00 00 	lea    rdx,[rip+0x74ae]        # 14000f1a0 <dtoa_CritSec>
   140007cf2:	48 01 d0             	add    rax,rdx
   140007cf5:	48 89 c1             	mov    rcx,rax
   140007cf8:	48 8b 05 39 85 00 00 	mov    rax,QWORD PTR [rip+0x8539]        # 140010238 <__imp_LeaveCriticalSection>
   140007cff:	ff d0                	call   rax
   140007d01:	90                   	nop
   140007d02:	48 83 c4 20          	add    rsp,0x20
   140007d06:	5d                   	pop    rbp
   140007d07:	c3                   	ret

0000000140007d08 <__lo0bits_D2A>:
   140007d08:	55                   	push   rbp
   140007d09:	48 89 e5             	mov    rbp,rsp
   140007d0c:	48 83 ec 10          	sub    rsp,0x10
   140007d10:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007d14:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d18:	8b 00                	mov    eax,DWORD PTR [rax]
   140007d1a:	f3 0f bc c0          	tzcnt  eax,eax
   140007d1e:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140007d21:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d25:	8b 10                	mov    edx,DWORD PTR [rax]
   140007d27:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007d2a:	89 c1                	mov    ecx,eax
   140007d2c:	d3 ea                	shr    edx,cl
   140007d2e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007d32:	89 10                	mov    DWORD PTR [rax],edx
   140007d34:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007d37:	48 83 c4 10          	add    rsp,0x10
   140007d3b:	5d                   	pop    rbp
   140007d3c:	c3                   	ret

0000000140007d3d <__hi0bits_D2A>:
   140007d3d:	55                   	push   rbp
   140007d3e:	48 89 e5             	mov    rbp,rsp
   140007d41:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d44:	0f bd 45 10          	bsr    eax,DWORD PTR [rbp+0x10]
   140007d48:	83 f0 1f             	xor    eax,0x1f
   140007d4b:	5d                   	pop    rbp
   140007d4c:	c3                   	ret

0000000140007d4d <__Balloc_D2A>:
   140007d4d:	55                   	push   rbp
   140007d4e:	48 89 e5             	mov    rbp,rsp
   140007d51:	48 83 ec 30          	sub    rsp,0x30
   140007d55:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140007d58:	b9 00 00 00 00       	mov    ecx,0x0
   140007d5d:	e8 30 fe ff ff       	call   140007b92 <dtoa_lock>
   140007d62:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007d66:	7f 48                	jg     140007db0 <__Balloc_D2A+0x63>
   140007d68:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007d6b:	48 98                	cdqe
   140007d6d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007d74:	00 
   140007d75:	48 8d 05 84 74 00 00 	lea    rax,[rip+0x7484]        # 14000f200 <freelist>
   140007d7c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
   140007d80:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007d84:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007d89:	74 25                	je     140007db0 <__Balloc_D2A+0x63>
   140007d8b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007d8f:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140007d92:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007d95:	48 63 d2             	movsxd rdx,edx
   140007d98:	48 8d 0c d5 00 00 00 	lea    rcx,[rdx*8+0x0]
   140007d9f:	00 
   140007da0:	48 8d 15 59 74 00 00 	lea    rdx,[rip+0x7459]        # 14000f200 <freelist>
   140007da7:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007dab:	e9 b1 00 00 00       	jmp    140007e61 <__Balloc_D2A+0x114>
   140007db0:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140007db3:	ba 01 00 00 00       	mov    edx,0x1
   140007db8:	89 c1                	mov    ecx,eax
   140007dba:	d3 e2                	shl    edx,cl
   140007dbc:	89 d0                	mov    eax,edx
   140007dbe:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140007dc1:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140007dc4:	83 e8 01             	sub    eax,0x1
   140007dc7:	48 98                	cdqe
   140007dc9:	48 c1 e0 02          	shl    rax,0x2
   140007dcd:	48 83 c0 27          	add    rax,0x27
   140007dd1:	48 c1 e8 03          	shr    rax,0x3
   140007dd5:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140007dd8:	83 7d 10 09          	cmp    DWORD PTR [rbp+0x10],0x9
   140007ddc:	7f 4e                	jg     140007e2c <__Balloc_D2A+0xdf>
   140007dde:	48 8b 15 ab 22 00 00 	mov    rdx,QWORD PTR [rip+0x22ab]        # 14000a090 <pmem_next>
   140007de5:	48 8d 05 74 74 00 00 	lea    rax,[rip+0x7474]        # 14000f260 <private_mem>
   140007dec:	48 29 c2             	sub    rdx,rax
   140007def:	48 89 d0             	mov    rax,rdx
   140007df2:	48 c1 f8 03          	sar    rax,0x3
   140007df6:	48 89 c2             	mov    rdx,rax
   140007df9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007dfc:	48 01 d0             	add    rax,rdx
   140007dff:	48 3d 20 01 00 00    	cmp    rax,0x120
   140007e05:	77 25                	ja     140007e2c <__Balloc_D2A+0xdf>
   140007e07:	48 8b 05 82 22 00 00 	mov    rax,QWORD PTR [rip+0x2282]        # 14000a090 <pmem_next>
   140007e0e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007e12:	48 8b 05 77 22 00 00 	mov    rax,QWORD PTR [rip+0x2277]        # 14000a090 <pmem_next>
   140007e19:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140007e1c:	48 c1 e2 03          	shl    rdx,0x3
   140007e20:	48 01 d0             	add    rax,rdx
   140007e23:	48 89 05 66 22 00 00 	mov    QWORD PTR [rip+0x2266],rax        # 14000a090 <pmem_next>
   140007e2a:	eb 21                	jmp    140007e4d <__Balloc_D2A+0x100>
   140007e2c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140007e2f:	48 c1 e0 03          	shl    rax,0x3
   140007e33:	48 89 c1             	mov    rcx,rax
   140007e36:	e8 e5 18 00 00       	call   140009720 <malloc>
   140007e3b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140007e3f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140007e44:	75 07                	jne    140007e4d <__Balloc_D2A+0x100>
   140007e46:	b8 00 00 00 00       	mov    eax,0x0
   140007e4b:	eb 3b                	jmp    140007e88 <__Balloc_D2A+0x13b>
   140007e4d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e51:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140007e54:	89 50 08             	mov    DWORD PTR [rax+0x8],edx
   140007e57:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e5b:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140007e5e:	89 50 0c             	mov    DWORD PTR [rax+0xc],edx
   140007e61:	b9 00 00 00 00       	mov    ecx,0x0
   140007e66:	e8 59 fe ff ff       	call   140007cc4 <dtoa_unlock>
   140007e6b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e6f:	c7 40 14 00 00 00 00 	mov    DWORD PTR [rax+0x14],0x0
   140007e76:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e7a:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140007e7d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e81:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   140007e84:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140007e88:	48 83 c4 30          	add    rsp,0x30
   140007e8c:	5d                   	pop    rbp
   140007e8d:	c3                   	ret

0000000140007e8e <__Bfree_D2A>:
   140007e8e:	55                   	push   rbp
   140007e8f:	48 89 e5             	mov    rbp,rsp
   140007e92:	48 83 ec 20          	sub    rsp,0x20
   140007e96:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007e9a:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140007e9f:	74 71                	je     140007f12 <__Bfree_D2A+0x84>
   140007ea1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ea5:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ea8:	83 f8 09             	cmp    eax,0x9
   140007eab:	7e 0e                	jle    140007ebb <__Bfree_D2A+0x2d>
   140007ead:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eb1:	48 89 c1             	mov    rcx,rax
   140007eb4:	e8 57 18 00 00       	call   140009710 <free>
   140007eb9:	eb 57                	jmp    140007f12 <__Bfree_D2A+0x84>
   140007ebb:	b9 00 00 00 00       	mov    ecx,0x0
   140007ec0:	e8 cd fc ff ff       	call   140007b92 <dtoa_lock>
   140007ec5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ec9:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007ecc:	48 98                	cdqe
   140007ece:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
   140007ed5:	00 
   140007ed6:	48 8d 05 23 73 00 00 	lea    rax,[rip+0x7323]        # 14000f200 <freelist>
   140007edd:	48 8b 14 02          	mov    rdx,QWORD PTR [rdx+rax*1]
   140007ee1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007ee5:	48 89 10             	mov    QWORD PTR [rax],rdx
   140007ee8:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007eec:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007eef:	48 98                	cdqe
   140007ef1:	48 8d 0c c5 00 00 00 	lea    rcx,[rax*8+0x0]
   140007ef8:	00 
   140007ef9:	48 8d 15 00 73 00 00 	lea    rdx,[rip+0x7300]        # 14000f200 <freelist>
   140007f00:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f04:	48 89 04 11          	mov    QWORD PTR [rcx+rdx*1],rax
   140007f08:	b9 00 00 00 00       	mov    ecx,0x0
   140007f0d:	e8 b2 fd ff ff       	call   140007cc4 <dtoa_unlock>
   140007f12:	90                   	nop
   140007f13:	48 83 c4 20          	add    rsp,0x20
   140007f17:	5d                   	pop    rbp
   140007f18:	c3                   	ret

0000000140007f19 <__multadd_D2A>:
   140007f19:	55                   	push   rbp
   140007f1a:	48 89 e5             	mov    rbp,rsp
   140007f1d:	48 83 ec 50          	sub    rsp,0x50
   140007f21:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140007f25:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   140007f28:	44 89 45 20          	mov    DWORD PTR [rbp+0x20],r8d
   140007f2c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f30:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007f33:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140007f36:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007f3a:	48 83 c0 18          	add    rax,0x18
   140007f3e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140007f42:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140007f49:	8b 45 20             	mov    eax,DWORD PTR [rbp+0x20]
   140007f4c:	48 98                	cdqe
   140007f4e:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f52:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f56:	8b 00                	mov    eax,DWORD PTR [rax]
   140007f58:	89 c2                	mov    edx,eax
   140007f5a:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140007f5d:	48 98                	cdqe
   140007f5f:	48 0f af d0          	imul   rdx,rax
   140007f63:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140007f67:	48 01 d0             	add    rax,rdx
   140007f6a:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140007f6e:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140007f72:	48 c1 e8 20          	shr    rax,0x20
   140007f76:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140007f7a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140007f7e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140007f82:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140007f86:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
   140007f8a:	89 10                	mov    DWORD PTR [rax],edx
   140007f8c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140007f90:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140007f93:	3b 45 e4             	cmp    eax,DWORD PTR [rbp-0x1c]
   140007f96:	7c ba                	jl     140007f52 <__multadd_D2A+0x39>
   140007f98:	48 83 7d e8 00       	cmp    QWORD PTR [rbp-0x18],0x0
   140007f9d:	0f 84 9a 00 00 00    	je     14000803d <__multadd_D2A+0x124>
   140007fa3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fa7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   140007faa:	39 45 e4             	cmp    DWORD PTR [rbp-0x1c],eax
   140007fad:	7c 67                	jl     140008016 <__multadd_D2A+0xfd>
   140007faf:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fb3:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140007fb6:	83 c0 01             	add    eax,0x1
   140007fb9:	89 c1                	mov    ecx,eax
   140007fbb:	e8 8d fd ff ff       	call   140007d4d <__Balloc_D2A>
   140007fc0:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140007fc4:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140007fc9:	75 07                	jne    140007fd2 <__multadd_D2A+0xb9>
   140007fcb:	b8 00 00 00 00       	mov    eax,0x0
   140007fd0:	eb 6f                	jmp    140008041 <__multadd_D2A+0x128>
   140007fd2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007fd6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140007fd9:	48 98                	cdqe
   140007fdb:	48 83 c0 02          	add    rax,0x2
   140007fdf:	48 8d 0c 85 00 00 00 	lea    rcx,[rax*4+0x0]
   140007fe6:	00 
   140007fe7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140007feb:	48 8d 50 10          	lea    rdx,[rax+0x10]
   140007fef:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140007ff3:	48 83 c0 10          	add    rax,0x10
   140007ff7:	49 89 c8             	mov    r8,rcx
   140007ffa:	48 89 c1             	mov    rcx,rax
   140007ffd:	e8 26 17 00 00       	call   140009728 <memcpy>
   140008002:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008006:	48 89 c1             	mov    rcx,rax
   140008009:	e8 80 fe ff ff       	call   140007e8e <__Bfree_D2A>
   14000800e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008012:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008016:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008019:	8d 50 01             	lea    edx,[rax+0x1]
   14000801c:	89 55 e4             	mov    DWORD PTR [rbp-0x1c],edx
   14000801f:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   140008023:	89 d1                	mov    ecx,edx
   140008025:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008029:	48 98                	cdqe
   14000802b:	48 83 c0 04          	add    rax,0x4
   14000802f:	89 4c 82 08          	mov    DWORD PTR [rdx+rax*4+0x8],ecx
   140008033:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008037:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   14000803a:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   14000803d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008041:	48 83 c4 50          	add    rsp,0x50
   140008045:	5d                   	pop    rbp
   140008046:	c3                   	ret

0000000140008047 <__i2b_D2A>:
   140008047:	55                   	push   rbp
   140008048:	48 89 e5             	mov    rbp,rsp
   14000804b:	48 83 ec 30          	sub    rsp,0x30
   14000804f:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   140008052:	b9 01 00 00 00       	mov    ecx,0x1
   140008057:	e8 f1 fc ff ff       	call   140007d4d <__Balloc_D2A>
   14000805c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008060:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008065:	75 07                	jne    14000806e <__i2b_D2A+0x27>
   140008067:	b8 00 00 00 00       	mov    eax,0x0
   14000806c:	eb 19                	jmp    140008087 <__i2b_D2A+0x40>
   14000806e:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   140008071:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008075:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008078:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000807c:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008083:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008087:	48 83 c4 30          	add    rsp,0x30
   14000808b:	5d                   	pop    rbp
   14000808c:	c3                   	ret

000000014000808d <__mult_D2A>:
   14000808d:	55                   	push   rbp
   14000808e:	48 89 e5             	mov    rbp,rsp
   140008091:	48 81 ec 90 00 00 00 	sub    rsp,0x90
   140008098:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000809c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400080a0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080a4:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   1400080a7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080ab:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080ae:	39 c2                	cmp    edx,eax
   1400080b0:	7d 18                	jge    1400080ca <__mult_D2A+0x3d>
   1400080b2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080b6:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400080ba:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080be:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400080c2:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400080c6:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   1400080ca:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080ce:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   1400080d1:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400080d4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080d8:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080db:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400080de:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400080e2:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400080e5:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
   1400080e8:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
   1400080eb:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   1400080ee:	01 d0                	add    eax,edx
   1400080f0:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   1400080f3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400080f7:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400080fa:	39 45 f8             	cmp    DWORD PTR [rbp-0x8],eax
   1400080fd:	7e 04                	jle    140008103 <__mult_D2A+0x76>
   1400080ff:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008103:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008106:	89 c1                	mov    ecx,eax
   140008108:	e8 40 fc ff ff       	call   140007d4d <__Balloc_D2A>
   14000810d:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008111:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
   140008116:	75 0a                	jne    140008122 <__mult_D2A+0x95>
   140008118:	b8 00 00 00 00       	mov    eax,0x0
   14000811d:	e9 88 01 00 00       	jmp    1400082aa <__mult_D2A+0x21d>
   140008122:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008126:	48 83 c0 18          	add    rax,0x18
   14000812a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000812e:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008131:	48 98                	cdqe
   140008133:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000813a:	00 
   14000813b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000813f:	48 01 d0             	add    rax,rdx
   140008142:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   140008146:	eb 0f                	jmp    140008157 <__mult_D2A+0xca>
   140008148:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000814c:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008152:	48 83 45 f0 04       	add    QWORD PTR [rbp-0x10],0x4
   140008157:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000815b:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   14000815f:	72 e7                	jb     140008148 <__mult_D2A+0xbb>
   140008161:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008165:	48 83 c0 18          	add    rax,0x18
   140008169:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   14000816d:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   140008170:	48 98                	cdqe
   140008172:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008179:	00 
   14000817a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   14000817e:	48 01 d0             	add    rax,rdx
   140008181:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008185:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008189:	48 83 c0 18          	add    rax,0x18
   14000818d:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008191:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
   140008194:	48 98                	cdqe
   140008196:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000819d:	00 
   14000819e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081a2:	48 01 d0             	add    rax,rdx
   1400081a5:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
   1400081a9:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400081ad:	48 83 c0 18          	add    rax,0x18
   1400081b1:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   1400081b5:	e9 95 00 00 00       	jmp    14000824f <__mult_D2A+0x1c2>
   1400081ba:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400081be:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081c2:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   1400081c6:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081c8:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
   1400081cb:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
   1400081cf:	74 79                	je     14000824a <__mult_D2A+0x1bd>
   1400081d1:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
   1400081d5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400081d9:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   1400081dd:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400081e1:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
   1400081e8:	00 
   1400081e9:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400081ed:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400081f1:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   1400081f5:	8b 00                	mov    eax,DWORD PTR [rax]
   1400081f7:	89 c2                	mov    edx,eax
   1400081f9:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
   1400081fc:	48 0f af d0          	imul   rdx,rax
   140008200:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008204:	8b 00                	mov    eax,DWORD PTR [rax]
   140008206:	89 c0                	mov    eax,eax
   140008208:	48 01 c2             	add    rdx,rax
   14000820b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000820f:	48 01 d0             	add    rax,rdx
   140008212:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
   140008216:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
   14000821a:	48 c1 e8 20          	shr    rax,0x20
   14000821e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008222:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008226:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000822a:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000822e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
   140008232:	89 10                	mov    DWORD PTR [rax],edx
   140008234:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008238:	48 3b 45 b0          	cmp    rax,QWORD PTR [rbp-0x50]
   14000823c:	72 ab                	jb     1400081e9 <__mult_D2A+0x15c>
   14000823e:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008242:	89 c2                	mov    edx,eax
   140008244:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008248:	89 10                	mov    DWORD PTR [rax],edx
   14000824a:	48 83 45 d8 04       	add    QWORD PTR [rbp-0x28],0x4
   14000824f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008253:	48 3b 45 a8          	cmp    rax,QWORD PTR [rbp-0x58]
   140008257:	0f 82 5d ff ff ff    	jb     1400081ba <__mult_D2A+0x12d>
   14000825d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   140008261:	48 83 c0 18          	add    rax,0x18
   140008265:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008269:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   14000826c:	48 98                	cdqe
   14000826e:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008275:	00 
   140008276:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   14000827a:	48 01 d0             	add    rax,rdx
   14000827d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008281:	eb 04                	jmp    140008287 <__mult_D2A+0x1fa>
   140008283:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   140008287:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   14000828b:	7e 0f                	jle    14000829c <__mult_D2A+0x20f>
   14000828d:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   140008292:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008296:	8b 00                	mov    eax,DWORD PTR [rax]
   140008298:	85 c0                	test   eax,eax
   14000829a:	74 e7                	je     140008283 <__mult_D2A+0x1f6>
   14000829c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400082a0:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400082a3:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400082a6:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
   1400082aa:	48 81 c4 90 00 00 00 	add    rsp,0x90
   1400082b1:	5d                   	pop    rbp
   1400082b2:	c3                   	ret

00000001400082b3 <__pow5mult_D2A>:
   1400082b3:	55                   	push   rbp
   1400082b4:	48 89 e5             	mov    rbp,rsp
   1400082b7:	48 83 ec 40          	sub    rsp,0x40
   1400082bb:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400082bf:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400082c2:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   1400082c5:	83 e0 03             	and    eax,0x3
   1400082c8:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400082cb:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   1400082cf:	74 41                	je     140008312 <__pow5mult_D2A+0x5f>
   1400082d1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   1400082d4:	83 e8 01             	sub    eax,0x1
   1400082d7:	48 98                	cdqe
   1400082d9:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400082e0:	00 
   1400082e1:	48 8d 05 b0 1d 00 00 	lea    rax,[rip+0x1db0]        # 14000a098 <p05.0>
   1400082e8:	8b 14 02             	mov    edx,DWORD PTR [rdx+rax*1]
   1400082eb:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400082ef:	41 b8 00 00 00 00    	mov    r8d,0x0
   1400082f5:	48 89 c1             	mov    rcx,rax
   1400082f8:	e8 1c fc ff ff       	call   140007f19 <__multadd_D2A>
   1400082fd:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   140008301:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140008306:	75 0a                	jne    140008312 <__pow5mult_D2A+0x5f>
   140008308:	b8 00 00 00 00       	mov    eax,0x0
   14000830d:	e9 58 01 00 00       	jmp    14000846a <__pow5mult_D2A+0x1b7>
   140008312:	c1 7d 18 02          	sar    DWORD PTR [rbp+0x18],0x2
   140008316:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   14000831a:	75 09                	jne    140008325 <__pow5mult_D2A+0x72>
   14000831c:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008320:	e9 45 01 00 00       	jmp    14000846a <__pow5mult_D2A+0x1b7>
   140008325:	48 8b 05 34 78 00 00 	mov    rax,QWORD PTR [rip+0x7834]        # 14000fb60 <p5s>
   14000832c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008330:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008335:	75 5e                	jne    140008395 <__pow5mult_D2A+0xe2>
   140008337:	b9 01 00 00 00       	mov    ecx,0x1
   14000833c:	e8 51 f8 ff ff       	call   140007b92 <dtoa_lock>
   140008341:	48 8b 05 18 78 00 00 	mov    rax,QWORD PTR [rip+0x7818]        # 14000fb60 <p5s>
   140008348:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000834c:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008351:	75 38                	jne    14000838b <__pow5mult_D2A+0xd8>
   140008353:	b9 71 02 00 00       	mov    ecx,0x271
   140008358:	e8 ea fc ff ff       	call   140008047 <__i2b_D2A>
   14000835d:	48 89 05 fc 77 00 00 	mov    QWORD PTR [rip+0x77fc],rax        # 14000fb60 <p5s>
   140008364:	48 8b 05 f5 77 00 00 	mov    rax,QWORD PTR [rip+0x77f5]        # 14000fb60 <p5s>
   14000836b:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000836f:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140008374:	75 0a                	jne    140008380 <__pow5mult_D2A+0xcd>
   140008376:	b8 00 00 00 00       	mov    eax,0x0
   14000837b:	e9 ea 00 00 00       	jmp    14000846a <__pow5mult_D2A+0x1b7>
   140008380:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008384:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000838b:	b9 01 00 00 00       	mov    ecx,0x1
   140008390:	e8 2f f9 ff ff       	call   140007cc4 <dtoa_unlock>
   140008395:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008398:	83 e0 01             	and    eax,0x1
   14000839b:	85 c0                	test   eax,eax
   14000839d:	74 39                	je     1400083d8 <__pow5mult_D2A+0x125>
   14000839f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   1400083a3:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083a7:	48 89 c1             	mov    rcx,rax
   1400083aa:	e8 de fc ff ff       	call   14000808d <__mult_D2A>
   1400083af:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400083b3:	48 83 7d e0 00       	cmp    QWORD PTR [rbp-0x20],0x0
   1400083b8:	75 0a                	jne    1400083c4 <__pow5mult_D2A+0x111>
   1400083ba:	b8 00 00 00 00       	mov    eax,0x0
   1400083bf:	e9 a6 00 00 00       	jmp    14000846a <__pow5mult_D2A+0x1b7>
   1400083c4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400083c8:	48 89 c1             	mov    rcx,rax
   1400083cb:	e8 be fa ff ff       	call   140007e8e <__Bfree_D2A>
   1400083d0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400083d4:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   1400083d8:	d1 7d 18             	sar    DWORD PTR [rbp+0x18],1
   1400083db:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   1400083df:	0f 84 80 00 00 00    	je     140008465 <__pow5mult_D2A+0x1b2>
   1400083e5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400083e9:	48 8b 00             	mov    rax,QWORD PTR [rax]
   1400083ec:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400083f0:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400083f5:	75 61                	jne    140008458 <__pow5mult_D2A+0x1a5>
   1400083f7:	b9 01 00 00 00       	mov    ecx,0x1
   1400083fc:	e8 91 f7 ff ff       	call   140007b92 <dtoa_lock>
   140008401:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008405:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008408:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000840c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008411:	75 3b                	jne    14000844e <__pow5mult_D2A+0x19b>
   140008413:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008417:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000841b:	48 89 c1             	mov    rcx,rax
   14000841e:	e8 6a fc ff ff       	call   14000808d <__mult_D2A>
   140008423:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
   140008427:	48 89 02             	mov    QWORD PTR [rdx],rax
   14000842a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000842e:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008431:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008435:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   14000843a:	75 07                	jne    140008443 <__pow5mult_D2A+0x190>
   14000843c:	b8 00 00 00 00       	mov    eax,0x0
   140008441:	eb 27                	jmp    14000846a <__pow5mult_D2A+0x1b7>
   140008443:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008447:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
   14000844e:	b9 01 00 00 00       	mov    ecx,0x1
   140008453:	e8 6c f8 ff ff       	call   140007cc4 <dtoa_unlock>
   140008458:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000845c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008460:	e9 30 ff ff ff       	jmp    140008395 <__pow5mult_D2A+0xe2>
   140008465:	90                   	nop
   140008466:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000846a:	48 83 c4 40          	add    rsp,0x40
   14000846e:	5d                   	pop    rbp
   14000846f:	c3                   	ret

0000000140008470 <__lshift_D2A>:
   140008470:	55                   	push   rbp
   140008471:	48 89 e5             	mov    rbp,rsp
   140008474:	48 83 ec 60          	sub    rsp,0x60
   140008478:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000847c:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   14000847f:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   140008482:	c1 f8 05             	sar    eax,0x5
   140008485:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
   140008488:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000848c:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   14000848f:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008492:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008496:	8b 50 14             	mov    edx,DWORD PTR [rax+0x14]
   140008499:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   14000849c:	01 d0                	add    eax,edx
   14000849e:	83 c0 01             	add    eax,0x1
   1400084a1:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400084a4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400084a8:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
   1400084ab:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400084ae:	eb 07                	jmp    1400084b7 <__lshift_D2A+0x47>
   1400084b0:	83 45 f8 01          	add    DWORD PTR [rbp-0x8],0x1
   1400084b4:	d1 65 fc             	shl    DWORD PTR [rbp-0x4],1
   1400084b7:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400084ba:	3b 45 fc             	cmp    eax,DWORD PTR [rbp-0x4]
   1400084bd:	7f f1                	jg     1400084b0 <__lshift_D2A+0x40>
   1400084bf:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400084c2:	89 c1                	mov    ecx,eax
   1400084c4:	e8 84 f8 ff ff       	call   140007d4d <__Balloc_D2A>
   1400084c9:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   1400084cd:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   1400084d2:	75 0a                	jne    1400084de <__lshift_D2A+0x6e>
   1400084d4:	b8 00 00 00 00       	mov    eax,0x0
   1400084d9:	e9 19 01 00 00       	jmp    1400085f7 <__lshift_D2A+0x187>
   1400084de:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400084e2:	48 83 c0 18          	add    rax,0x18
   1400084e6:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400084ea:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   1400084f1:	eb 16                	jmp    140008509 <__lshift_D2A+0x99>
   1400084f3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400084f7:	48 8d 50 04          	lea    rdx,[rax+0x4]
   1400084fb:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   1400084ff:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140008505:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
   140008509:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   14000850c:	3b 45 d8             	cmp    eax,DWORD PTR [rbp-0x28]
   14000850f:	7c e2                	jl     1400084f3 <__lshift_D2A+0x83>
   140008511:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008515:	48 83 c0 18          	add    rax,0x18
   140008519:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   14000851d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008521:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008524:	48 98                	cdqe
   140008526:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000852d:	00 
   14000852e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008532:	48 01 d0             	add    rax,rdx
   140008535:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   140008539:	83 65 18 1f          	and    DWORD PTR [rbp+0x18],0x1f
   14000853d:	83 7d 18 00          	cmp    DWORD PTR [rbp+0x18],0x0
   140008541:	74 71                	je     1400085b4 <__lshift_D2A+0x144>
   140008543:	b8 20 00 00 00       	mov    eax,0x20
   140008548:	2b 45 18             	sub    eax,DWORD PTR [rbp+0x18]
   14000854b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000854e:	c7 45 dc 00 00 00 00 	mov    DWORD PTR [rbp-0x24],0x0
   140008555:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008559:	8b 10                	mov    edx,DWORD PTR [rax]
   14000855b:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000855e:	89 c1                	mov    ecx,eax
   140008560:	d3 e2                	shl    edx,cl
   140008562:	89 d1                	mov    ecx,edx
   140008564:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008568:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000856c:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008570:	0b 4d dc             	or     ecx,DWORD PTR [rbp-0x24]
   140008573:	89 ca                	mov    edx,ecx
   140008575:	89 10                	mov    DWORD PTR [rax],edx
   140008577:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   14000857b:	48 8d 50 04          	lea    rdx,[rax+0x4]
   14000857f:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   140008583:	8b 10                	mov    edx,DWORD PTR [rax]
   140008585:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008588:	89 c1                	mov    ecx,eax
   14000858a:	d3 ea                	shr    edx,cl
   14000858c:	89 d0                	mov    eax,edx
   14000858e:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008591:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008595:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   140008599:	72 ba                	jb     140008555 <__lshift_D2A+0xe5>
   14000859b:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   14000859f:	8b 55 dc             	mov    edx,DWORD PTR [rbp-0x24]
   1400085a2:	89 10                	mov    DWORD PTR [rax],edx
   1400085a4:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085a8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400085aa:	85 c0                	test   eax,eax
   1400085ac:	74 2c                	je     1400085da <__lshift_D2A+0x16a>
   1400085ae:	83 45 f4 01          	add    DWORD PTR [rbp-0xc],0x1
   1400085b2:	eb 26                	jmp    1400085da <__lshift_D2A+0x16a>
   1400085b4:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
   1400085b8:	48 8d 42 04          	lea    rax,[rdx+0x4]
   1400085bc:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400085c0:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400085c4:	48 8d 48 04          	lea    rcx,[rax+0x4]
   1400085c8:	48 89 4d e0          	mov    QWORD PTR [rbp-0x20],rcx
   1400085cc:	8b 12                	mov    edx,DWORD PTR [rdx]
   1400085ce:	89 10                	mov    DWORD PTR [rax],edx
   1400085d0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400085d4:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   1400085d8:	72 da                	jb     1400085b4 <__lshift_D2A+0x144>
   1400085da:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   1400085dd:	8d 50 ff             	lea    edx,[rax-0x1]
   1400085e0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085e4:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400085e7:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400085eb:	48 89 c1             	mov    rcx,rax
   1400085ee:	e8 9b f8 ff ff       	call   140007e8e <__Bfree_D2A>
   1400085f3:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400085f7:	48 83 c4 60          	add    rsp,0x60
   1400085fb:	5d                   	pop    rbp
   1400085fc:	c3                   	ret

00000001400085fd <__cmp_D2A>:
   1400085fd:	55                   	push   rbp
   1400085fe:	48 89 e5             	mov    rbp,rsp
   140008601:	48 83 ec 30          	sub    rsp,0x30
   140008605:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008609:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   14000860d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008611:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008614:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   140008617:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000861b:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   14000861e:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
   140008621:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008624:	29 45 ec             	sub    DWORD PTR [rbp-0x14],eax
   140008627:	83 7d ec 00          	cmp    DWORD PTR [rbp-0x14],0x0
   14000862b:	74 08                	je     140008635 <__cmp_D2A+0x38>
   14000862d:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008630:	e9 92 00 00 00       	jmp    1400086c7 <__cmp_D2A+0xca>
   140008635:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008639:	48 83 c0 18          	add    rax,0x18
   14000863d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140008641:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008644:	48 98                	cdqe
   140008646:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   14000864d:	00 
   14000864e:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008652:	48 01 d0             	add    rax,rdx
   140008655:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008659:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000865d:	48 83 c0 18          	add    rax,0x18
   140008661:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008665:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
   140008668:	48 98                	cdqe
   14000866a:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   140008671:	00 
   140008672:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
   140008676:	48 01 d0             	add    rax,rdx
   140008679:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000867d:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008682:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008686:	8b 10                	mov    edx,DWORD PTR [rax]
   140008688:	48 83 6d f0 04       	sub    QWORD PTR [rbp-0x10],0x4
   14000868d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008691:	8b 00                	mov    eax,DWORD PTR [rax]
   140008693:	39 c2                	cmp    edx,eax
   140008695:	74 1e                	je     1400086b5 <__cmp_D2A+0xb8>
   140008697:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000869b:	8b 10                	mov    edx,DWORD PTR [rax]
   14000869d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400086a1:	8b 00                	mov    eax,DWORD PTR [rax]
   1400086a3:	39 c2                	cmp    edx,eax
   1400086a5:	73 07                	jae    1400086ae <__cmp_D2A+0xb1>
   1400086a7:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400086ac:	eb 19                	jmp    1400086c7 <__cmp_D2A+0xca>
   1400086ae:	b8 01 00 00 00       	mov    eax,0x1
   1400086b3:	eb 12                	jmp    1400086c7 <__cmp_D2A+0xca>
   1400086b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400086b9:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400086bd:	73 02                	jae    1400086c1 <__cmp_D2A+0xc4>
   1400086bf:	eb bc                	jmp    14000867d <__cmp_D2A+0x80>
   1400086c1:	90                   	nop
   1400086c2:	b8 00 00 00 00       	mov    eax,0x0
   1400086c7:	48 83 c4 30          	add    rsp,0x30
   1400086cb:	5d                   	pop    rbp
   1400086cc:	c3                   	ret

00000001400086cd <__diff_D2A>:
   1400086cd:	55                   	push   rbp
   1400086ce:	48 89 e5             	mov    rbp,rsp
   1400086d1:	48 83 ec 70          	sub    rsp,0x70
   1400086d5:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400086d9:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400086dd:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   1400086e1:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400086e5:	48 89 c1             	mov    rcx,rax
   1400086e8:	e8 10 ff ff ff       	call   1400085fd <__cmp_D2A>
   1400086ed:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400086f0:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400086f4:	75 3e                	jne    140008734 <__diff_D2A+0x67>
   1400086f6:	b9 00 00 00 00       	mov    ecx,0x0
   1400086fb:	e8 4d f6 ff ff       	call   140007d4d <__Balloc_D2A>
   140008700:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008704:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008709:	75 0a                	jne    140008715 <__diff_D2A+0x48>
   14000870b:	b8 00 00 00 00       	mov    eax,0x0
   140008710:	e9 ab 01 00 00       	jmp    1400088c0 <__diff_D2A+0x1f3>
   140008715:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008719:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008720:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008724:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
   14000872b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000872f:	e9 8c 01 00 00       	jmp    1400088c0 <__diff_D2A+0x1f3>
   140008734:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008738:	79 21                	jns    14000875b <__diff_D2A+0x8e>
   14000873a:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000873e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008742:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008746:	48 89 45 10          	mov    QWORD PTR [rbp+0x10],rax
   14000874a:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   14000874e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140008752:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   140008759:	eb 07                	jmp    140008762 <__diff_D2A+0x95>
   14000875b:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140008762:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008766:	8b 40 08             	mov    eax,DWORD PTR [rax+0x8]
   140008769:	89 c1                	mov    ecx,eax
   14000876b:	e8 dd f5 ff ff       	call   140007d4d <__Balloc_D2A>
   140008770:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
   140008774:	48 83 7d d0 00       	cmp    QWORD PTR [rbp-0x30],0x0
   140008779:	75 0a                	jne    140008785 <__diff_D2A+0xb8>
   14000877b:	b8 00 00 00 00       	mov    eax,0x0
   140008780:	e9 3b 01 00 00       	jmp    1400088c0 <__diff_D2A+0x1f3>
   140008785:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   140008789:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   14000878c:	89 50 10             	mov    DWORD PTR [rax+0x10],edx
   14000878f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008793:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008796:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008799:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000879d:	48 83 c0 18          	add    rax,0x18
   1400087a1:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400087a5:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400087a8:	48 98                	cdqe
   1400087aa:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087b1:	00 
   1400087b2:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   1400087b6:	48 01 d0             	add    rax,rdx
   1400087b9:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
   1400087bd:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400087c1:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400087c4:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
   1400087c7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400087cb:	48 83 c0 18          	add    rax,0x18
   1400087cf:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   1400087d3:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
   1400087d6:	48 98                	cdqe
   1400087d8:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400087df:	00 
   1400087e0:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   1400087e4:	48 01 d0             	add    rax,rdx
   1400087e7:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
   1400087eb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400087ef:	48 83 c0 18          	add    rax,0x18
   1400087f3:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400087f7:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
   1400087fe:	00 
   1400087ff:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008803:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008807:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   14000880b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000880d:	89 c1                	mov    ecx,eax
   14000880f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008813:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008817:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
   14000881b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000881d:	89 c2                	mov    edx,eax
   14000881f:	48 89 c8             	mov    rax,rcx
   140008822:	48 29 d0             	sub    rax,rdx
   140008825:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   140008829:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   14000882d:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008831:	48 c1 e8 20          	shr    rax,0x20
   140008835:	83 e0 01             	and    eax,0x1
   140008838:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   14000883c:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008840:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008844:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   140008848:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   14000884c:	89 10                	mov    DWORD PTR [rax],edx
   14000884e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008852:	48 3b 45 b8          	cmp    rax,QWORD PTR [rbp-0x48]
   140008856:	72 a7                	jb     1400087ff <__diff_D2A+0x132>
   140008858:	eb 39                	jmp    140008893 <__diff_D2A+0x1c6>
   14000885a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000885e:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008862:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   140008866:	8b 00                	mov    eax,DWORD PTR [rax]
   140008868:	89 c0                	mov    eax,eax
   14000886a:	48 2b 45 d8          	sub    rax,QWORD PTR [rbp-0x28]
   14000886e:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
   140008872:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
   140008876:	48 c1 e8 20          	shr    rax,0x20
   14000887a:	83 e0 01             	and    eax,0x1
   14000887d:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
   140008881:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   140008885:	48 8d 50 04          	lea    rdx,[rax+0x4]
   140008889:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
   14000888d:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
   140008891:	89 10                	mov    DWORD PTR [rax],edx
   140008893:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008897:	48 3b 45 c8          	cmp    rax,QWORD PTR [rbp-0x38]
   14000889b:	72 bd                	jb     14000885a <__diff_D2A+0x18d>
   14000889d:	eb 04                	jmp    1400088a3 <__diff_D2A+0x1d6>
   14000889f:	83 6d f8 01          	sub    DWORD PTR [rbp-0x8],0x1
   1400088a3:	48 83 6d e0 04       	sub    QWORD PTR [rbp-0x20],0x4
   1400088a8:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400088ac:	8b 00                	mov    eax,DWORD PTR [rax]
   1400088ae:	85 c0                	test   eax,eax
   1400088b0:	74 ed                	je     14000889f <__diff_D2A+0x1d2>
   1400088b2:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400088b6:	8b 55 f8             	mov    edx,DWORD PTR [rbp-0x8]
   1400088b9:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   1400088bc:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
   1400088c0:	48 83 c4 70          	add    rsp,0x70
   1400088c4:	5d                   	pop    rbp
   1400088c5:	c3                   	ret

00000001400088c6 <__b2d_D2A>:
   1400088c6:	55                   	push   rbp
   1400088c7:	48 89 e5             	mov    rbp,rsp
   1400088ca:	48 83 ec 50          	sub    rsp,0x50
   1400088ce:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400088d2:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   1400088d6:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088da:	48 83 c0 18          	add    rax,0x18
   1400088de:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   1400088e2:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400088e6:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   1400088e9:	48 98                	cdqe
   1400088eb:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
   1400088f2:	00 
   1400088f3:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
   1400088f7:	48 01 d0             	add    rax,rdx
   1400088fa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   1400088fe:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008903:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008907:	8b 00                	mov    eax,DWORD PTR [rax]
   140008909:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   14000890c:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   14000890f:	89 c1                	mov    ecx,eax
   140008911:	e8 27 f4 ff ff       	call   140007d3d <__hi0bits_D2A>
   140008916:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008919:	b8 20 00 00 00       	mov    eax,0x20
   14000891e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008921:	89 c2                	mov    edx,eax
   140008923:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008927:	89 10                	mov    DWORD PTR [rax],edx
   140008929:	83 7d dc 0a          	cmp    DWORD PTR [rbp-0x24],0xa
   14000892d:	7f 66                	jg     140008995 <__b2d_D2A+0xcf>
   14000892f:	b8 0b 00 00 00       	mov    eax,0xb
   140008934:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008937:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000893a:	89 c1                	mov    ecx,eax
   14000893c:	d3 ea                	shr    edx,cl
   14000893e:	89 d0                	mov    eax,edx
   140008940:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008945:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008948:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000894c:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   140008950:	73 10                	jae    140008962 <__b2d_D2A+0x9c>
   140008952:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   140008957:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000895b:	8b 00                	mov    eax,DWORD PTR [rax]
   14000895d:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008960:	eb 07                	jmp    140008969 <__b2d_D2A+0xa3>
   140008962:	c7 45 f4 00 00 00 00 	mov    DWORD PTR [rbp-0xc],0x0
   140008969:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   14000896c:	83 c0 15             	add    eax,0x15
   14000896f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008972:	89 c1                	mov    ecx,eax
   140008974:	d3 e2                	shl    edx,cl
   140008976:	41 89 d0             	mov    r8d,edx
   140008979:	b8 0b 00 00 00       	mov    eax,0xb
   14000897e:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008981:	8b 55 f4             	mov    edx,DWORD PTR [rbp-0xc]
   140008984:	89 c1                	mov    ecx,eax
   140008986:	d3 ea                	shr    edx,cl
   140008988:	89 d0                	mov    eax,edx
   14000898a:	44 09 c0             	or     eax,r8d
   14000898d:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008990:	e9 ac 00 00 00       	jmp    140008a41 <__b2d_D2A+0x17b>
   140008995:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008999:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   14000899d:	73 10                	jae    1400089af <__b2d_D2A+0xe9>
   14000899f:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400089a4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089a8:	8b 00                	mov    eax,DWORD PTR [rax]
   1400089aa:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
   1400089ad:	eb 07                	jmp    1400089b6 <__b2d_D2A+0xf0>
   1400089af:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
   1400089b6:	83 6d dc 0b          	sub    DWORD PTR [rbp-0x24],0xb
   1400089ba:	83 7d dc 00          	cmp    DWORD PTR [rbp-0x24],0x0
   1400089be:	74 70                	je     140008a30 <__b2d_D2A+0x16a>
   1400089c0:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   1400089c3:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   1400089c6:	89 c1                	mov    ecx,eax
   1400089c8:	d3 e2                	shl    edx,cl
   1400089ca:	41 89 d0             	mov    r8d,edx
   1400089cd:	b8 20 00 00 00       	mov    eax,0x20
   1400089d2:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   1400089d5:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   1400089d8:	89 c1                	mov    ecx,eax
   1400089da:	d3 ea                	shr    edx,cl
   1400089dc:	89 d0                	mov    eax,edx
   1400089de:	44 09 c0             	or     eax,r8d
   1400089e1:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   1400089e6:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   1400089e9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089ed:	48 39 45 e0          	cmp    QWORD PTR [rbp-0x20],rax
   1400089f1:	73 10                	jae    140008a03 <__b2d_D2A+0x13d>
   1400089f3:	48 83 6d f8 04       	sub    QWORD PTR [rbp-0x8],0x4
   1400089f8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   1400089fc:	8b 00                	mov    eax,DWORD PTR [rax]
   1400089fe:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140008a01:	eb 07                	jmp    140008a0a <__b2d_D2A+0x144>
   140008a03:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
   140008a0a:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a0d:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
   140008a10:	89 c1                	mov    ecx,eax
   140008a12:	d3 e2                	shl    edx,cl
   140008a14:	41 89 d0             	mov    r8d,edx
   140008a17:	b8 20 00 00 00       	mov    eax,0x20
   140008a1c:	2b 45 dc             	sub    eax,DWORD PTR [rbp-0x24]
   140008a1f:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   140008a22:	89 c1                	mov    ecx,eax
   140008a24:	d3 ea                	shr    edx,cl
   140008a26:	89 d0                	mov    eax,edx
   140008a28:	44 09 c0             	or     eax,r8d
   140008a2b:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a2e:	eb 11                	jmp    140008a41 <__b2d_D2A+0x17b>
   140008a30:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008a33:	0d 00 00 f0 3f       	or     eax,0x3ff00000
   140008a38:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008a3b:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
   140008a3e:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008a41:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
   140008a46:	48 83 c4 50          	add    rsp,0x50
   140008a4a:	5d                   	pop    rbp
   140008a4b:	c3                   	ret

0000000140008a4c <__d2b_D2A>:
   140008a4c:	55                   	push   rbp
   140008a4d:	53                   	push   rbx
   140008a4e:	48 83 ec 58          	sub    rsp,0x58
   140008a52:	48 8d 6c 24 50       	lea    rbp,[rsp+0x50]
   140008a57:	f2 0f 11 45 20       	movsd  QWORD PTR [rbp+0x20],xmm0
   140008a5c:	48 89 55 28          	mov    QWORD PTR [rbp+0x28],rdx
   140008a60:	4c 89 45 30          	mov    QWORD PTR [rbp+0x30],r8
   140008a64:	f2 0f 10 45 20       	movsd  xmm0,QWORD PTR [rbp+0x20]
   140008a69:	f2 0f 11 45 d8       	movsd  QWORD PTR [rbp-0x28],xmm0
   140008a6e:	b9 01 00 00 00       	mov    ecx,0x1
   140008a73:	e8 d5 f2 ff ff       	call   140007d4d <__Balloc_D2A>
   140008a78:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   140008a7c:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   140008a81:	75 0a                	jne    140008a8d <__d2b_D2A+0x41>
   140008a83:	b8 00 00 00 00       	mov    eax,0x0
   140008a88:	e9 68 01 00 00       	jmp    140008bf5 <__d2b_D2A+0x1a9>
   140008a8d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008a91:	48 83 c0 18          	add    rax,0x18
   140008a95:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140008a99:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008a9c:	25 ff ff 0f 00       	and    eax,0xfffff
   140008aa1:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008aa4:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008aa7:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008aac:	89 45 dc             	mov    DWORD PTR [rbp-0x24],eax
   140008aaf:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
   140008ab2:	c1 e8 14             	shr    eax,0x14
   140008ab5:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
   140008ab8:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008abc:	74 0b                	je     140008ac9 <__d2b_D2A+0x7d>
   140008abe:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
   140008ac1:	0d 00 00 10 00       	or     eax,0x100000
   140008ac6:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008ac9:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
   140008acc:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
   140008acf:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008ad2:	85 c0                	test   eax,eax
   140008ad4:	74 7b                	je     140008b51 <__d2b_D2A+0x105>
   140008ad6:	48 8d 45 d4          	lea    rax,[rbp-0x2c]
   140008ada:	48 89 c1             	mov    rcx,rax
   140008add:	e8 26 f2 ff ff       	call   140007d08 <__lo0bits_D2A>
   140008ae2:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008ae5:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008ae9:	74 2b                	je     140008b16 <__d2b_D2A+0xca>
   140008aeb:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008aee:	b8 20 00 00 00       	mov    eax,0x20
   140008af3:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008af6:	89 c1                	mov    ecx,eax
   140008af8:	d3 e2                	shl    edx,cl
   140008afa:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
   140008afd:	09 c2                	or     edx,eax
   140008aff:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b03:	89 10                	mov    DWORD PTR [rax],edx
   140008b05:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b08:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b0b:	89 c1                	mov    ecx,eax
   140008b0d:	d3 ea                	shr    edx,cl
   140008b0f:	89 d0                	mov    eax,edx
   140008b11:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
   140008b14:	eb 09                	jmp    140008b1f <__d2b_D2A+0xd3>
   140008b16:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
   140008b19:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b1d:	89 10                	mov    DWORD PTR [rax],edx
   140008b1f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b23:	48 83 c0 04          	add    rax,0x4
   140008b27:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b2a:	89 10                	mov    DWORD PTR [rax],edx
   140008b2c:	8b 00                	mov    eax,DWORD PTR [rax]
   140008b2e:	85 c0                	test   eax,eax
   140008b30:	74 07                	je     140008b39 <__d2b_D2A+0xed>
   140008b32:	ba 02 00 00 00       	mov    edx,0x2
   140008b37:	eb 05                	jmp    140008b3e <__d2b_D2A+0xf2>
   140008b39:	ba 01 00 00 00       	mov    edx,0x1
   140008b3e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b42:	89 50 14             	mov    DWORD PTR [rax+0x14],edx
   140008b45:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b49:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b4c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b4f:	eb 31                	jmp    140008b82 <__d2b_D2A+0x136>
   140008b51:	48 8d 45 d0          	lea    rax,[rbp-0x30]
   140008b55:	48 89 c1             	mov    rcx,rax
   140008b58:	e8 ab f1 ff ff       	call   140007d08 <__lo0bits_D2A>
   140008b5d:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008b60:	8b 55 d0             	mov    edx,DWORD PTR [rbp-0x30]
   140008b63:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008b67:	89 10                	mov    DWORD PTR [rax],edx
   140008b69:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b6d:	c7 40 14 01 00 00 00 	mov    DWORD PTR [rax+0x14],0x1
   140008b74:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008b78:	8b 40 14             	mov    eax,DWORD PTR [rax+0x14]
   140008b7b:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008b7e:	83 45 f8 20          	add    DWORD PTR [rbp-0x8],0x20
   140008b82:	83 7d e4 00          	cmp    DWORD PTR [rbp-0x1c],0x0
   140008b86:	74 26                	je     140008bae <__d2b_D2A+0x162>
   140008b88:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008b8b:	8d 90 cd fb ff ff    	lea    edx,[rax-0x433]
   140008b91:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008b94:	01 c2                	add    edx,eax
   140008b96:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008b9a:	89 10                	mov    DWORD PTR [rax],edx
   140008b9c:	b8 35 00 00 00       	mov    eax,0x35
   140008ba1:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008ba4:	89 c2                	mov    edx,eax
   140008ba6:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008baa:	89 10                	mov    DWORD PTR [rax],edx
   140008bac:	eb 43                	jmp    140008bf1 <__d2b_D2A+0x1a5>
   140008bae:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008bb1:	8d 90 ce fb ff ff    	lea    edx,[rax-0x432]
   140008bb7:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008bba:	01 c2                	add    edx,eax
   140008bbc:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140008bc0:	89 10                	mov    DWORD PTR [rax],edx
   140008bc2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008bc5:	c1 e0 05             	shl    eax,0x5
   140008bc8:	89 c3                	mov    ebx,eax
   140008bca:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008bcd:	48 98                	cdqe
   140008bcf:	48 c1 e0 02          	shl    rax,0x2
   140008bd3:	48 8d 50 fc          	lea    rdx,[rax-0x4]
   140008bd7:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140008bdb:	48 01 d0             	add    rax,rdx
   140008bde:	8b 00                	mov    eax,DWORD PTR [rax]
   140008be0:	89 c1                	mov    ecx,eax
   140008be2:	e8 56 f1 ff ff       	call   140007d3d <__hi0bits_D2A>
   140008be7:	29 c3                	sub    ebx,eax
   140008be9:	89 da                	mov    edx,ebx
   140008beb:	48 8b 45 30          	mov    rax,QWORD PTR [rbp+0x30]
   140008bef:	89 10                	mov    DWORD PTR [rax],edx
   140008bf1:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   140008bf5:	48 83 c4 58          	add    rsp,0x58
   140008bf9:	5b                   	pop    rbx
   140008bfa:	5d                   	pop    rbp
   140008bfb:	c3                   	ret

0000000140008bfc <__strcp_D2A>:
   140008bfc:	55                   	push   rbp
   140008bfd:	48 89 e5             	mov    rbp,rsp
   140008c00:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008c04:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008c08:	eb 05                	jmp    140008c0f <__strcp_D2A+0x13>
   140008c0a:	48 83 45 10 01       	add    QWORD PTR [rbp+0x10],0x1
   140008c0f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140008c13:	48 8d 50 01          	lea    rdx,[rax+0x1]
   140008c17:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008c1b:	0f b6 10             	movzx  edx,BYTE PTR [rax]
   140008c1e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c22:	88 10                	mov    BYTE PTR [rax],dl
   140008c24:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c28:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008c2b:	84 c0                	test   al,al
   140008c2d:	75 db                	jne    140008c0a <__strcp_D2A+0xe>
   140008c2f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008c33:	5d                   	pop    rbp
   140008c34:	c3                   	ret
   140008c35:	90                   	nop
   140008c36:	90                   	nop
   140008c37:	90                   	nop
   140008c38:	90                   	nop
   140008c39:	90                   	nop
   140008c3a:	90                   	nop
   140008c3b:	90                   	nop
   140008c3c:	90                   	nop
   140008c3d:	90                   	nop
   140008c3e:	90                   	nop
   140008c3f:	90                   	nop

0000000140008c40 <__fpclassify>:
   140008c40:	55                   	push   rbp
   140008c41:	48 89 e5             	mov    rbp,rsp
   140008c44:	48 83 ec 10          	sub    rsp,0x10
   140008c48:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008c4d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008c52:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008c57:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008c5a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008c5d:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008c60:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
   140008c63:	81 e2 ff ff 0f 00    	and    edx,0xfffff
   140008c69:	09 d0                	or     eax,edx
   140008c6b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008c6e:	81 65 fc 00 00 f0 7f 	and    DWORD PTR [rbp-0x4],0x7ff00000
   140008c75:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008c78:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008c7b:	85 c0                	test   eax,eax
   140008c7d:	75 07                	jne    140008c86 <__fpclassify+0x46>
   140008c7f:	b8 00 40 00 00       	mov    eax,0x4000
   140008c84:	eb 2f                	jmp    140008cb5 <__fpclassify+0x75>
   140008c86:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008c8a:	75 07                	jne    140008c93 <__fpclassify+0x53>
   140008c8c:	b8 00 44 00 00       	mov    eax,0x4400
   140008c91:	eb 22                	jmp    140008cb5 <__fpclassify+0x75>
   140008c93:	81 7d fc 00 00 f0 7f 	cmp    DWORD PTR [rbp-0x4],0x7ff00000
   140008c9a:	75 14                	jne    140008cb0 <__fpclassify+0x70>
   140008c9c:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
   140008ca0:	74 07                	je     140008ca9 <__fpclassify+0x69>
   140008ca2:	b8 00 01 00 00       	mov    eax,0x100
   140008ca7:	eb 0c                	jmp    140008cb5 <__fpclassify+0x75>
   140008ca9:	b8 00 05 00 00       	mov    eax,0x500
   140008cae:	eb 05                	jmp    140008cb5 <__fpclassify+0x75>
   140008cb0:	b8 00 04 00 00       	mov    eax,0x400
   140008cb5:	48 83 c4 10          	add    rsp,0x10
   140008cb9:	5d                   	pop    rbp
   140008cba:	c3                   	ret
   140008cbb:	90                   	nop
   140008cbc:	90                   	nop
   140008cbd:	90                   	nop
   140008cbe:	90                   	nop
   140008cbf:	90                   	nop

0000000140008cc0 <__fpclassifyl>:
   140008cc0:	55                   	push   rbp
   140008cc1:	53                   	push   rbx
   140008cc2:	48 83 ec 38          	sub    rsp,0x38
   140008cc6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008ccb:	48 89 cb             	mov    rbx,rcx
   140008cce:	db 2b                	fld    TBYTE PTR [rbx]
   140008cd0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008cd3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008cd6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008cd9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008cdd:	98                   	cwde
   140008cde:	25 ff 7f 00 00       	and    eax,0x7fff
   140008ce3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008ce6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   140008cea:	75 25                	jne    140008d11 <__fpclassifyl+0x51>
   140008cec:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008cef:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008cf2:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008cf5:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008cf8:	85 c0                	test   eax,eax
   140008cfa:	75 07                	jne    140008d03 <__fpclassifyl+0x43>
   140008cfc:	b8 00 40 00 00       	mov    eax,0x4000
   140008d01:	eb 3d                	jmp    140008d40 <__fpclassifyl+0x80>
   140008d03:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d06:	85 c0                	test   eax,eax
   140008d08:	78 31                	js     140008d3b <__fpclassifyl+0x7b>
   140008d0a:	b8 00 44 00 00       	mov    eax,0x4400
   140008d0f:	eb 2f                	jmp    140008d40 <__fpclassifyl+0x80>
   140008d11:	81 7d fc ff 7f 00 00 	cmp    DWORD PTR [rbp-0x4],0x7fff
   140008d18:	75 21                	jne    140008d3b <__fpclassifyl+0x7b>
   140008d1a:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
   140008d1d:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d22:	89 c2                	mov    edx,eax
   140008d24:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008d27:	09 d0                	or     eax,edx
   140008d29:	85 c0                	test   eax,eax
   140008d2b:	75 07                	jne    140008d34 <__fpclassifyl+0x74>
   140008d2d:	b8 00 05 00 00       	mov    eax,0x500
   140008d32:	eb 0c                	jmp    140008d40 <__fpclassifyl+0x80>
   140008d34:	b8 00 01 00 00       	mov    eax,0x100
   140008d39:	eb 05                	jmp    140008d40 <__fpclassifyl+0x80>
   140008d3b:	b8 00 04 00 00       	mov    eax,0x400
   140008d40:	48 83 c4 38          	add    rsp,0x38
   140008d44:	5b                   	pop    rbx
   140008d45:	5d                   	pop    rbp
   140008d46:	c3                   	ret
   140008d47:	90                   	nop
   140008d48:	90                   	nop
   140008d49:	90                   	nop
   140008d4a:	90                   	nop
   140008d4b:	90                   	nop
   140008d4c:	90                   	nop
   140008d4d:	90                   	nop
   140008d4e:	90                   	nop
   140008d4f:	90                   	nop

0000000140008d50 <__isnan>:
   140008d50:	55                   	push   rbp
   140008d51:	48 89 e5             	mov    rbp,rsp
   140008d54:	48 83 ec 10          	sub    rsp,0x10
   140008d58:	f2 0f 11 45 10       	movsd  QWORD PTR [rbp+0x10],xmm0
   140008d5d:	f2 0f 10 45 10       	movsd  xmm0,QWORD PTR [rbp+0x10]
   140008d62:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0
   140008d67:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
   140008d6a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008d6d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008d70:	25 ff ff ff 7f       	and    eax,0x7fffffff
   140008d75:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d78:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008d7b:	f7 d8                	neg    eax
   140008d7d:	0b 45 fc             	or     eax,DWORD PTR [rbp-0x4]
   140008d80:	c1 e8 1f             	shr    eax,0x1f
   140008d83:	89 c2                	mov    edx,eax
   140008d85:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d88:	09 d0                	or     eax,edx
   140008d8a:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d8d:	b8 00 00 f0 7f       	mov    eax,0x7ff00000
   140008d92:	2b 45 f8             	sub    eax,DWORD PTR [rbp-0x8]
   140008d95:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008d98:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008d9b:	c1 f8 1f             	sar    eax,0x1f
   140008d9e:	48 83 c4 10          	add    rsp,0x10
   140008da2:	5d                   	pop    rbp
   140008da3:	c3                   	ret
   140008da4:	90                   	nop
   140008da5:	90                   	nop
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

0000000140008db0 <__isnanl>:
   140008db0:	55                   	push   rbp
   140008db1:	53                   	push   rbx
   140008db2:	48 83 ec 38          	sub    rsp,0x38
   140008db6:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
   140008dbb:	48 89 cb             	mov    rbx,rcx
   140008dbe:	db 2b                	fld    TBYTE PTR [rbx]
   140008dc0:	db 7d d0             	fstp   TBYTE PTR [rbp-0x30]
   140008dc3:	db 6d d0             	fld    TBYTE PTR [rbp-0x30]
   140008dc6:	db 7d e0             	fstp   TBYTE PTR [rbp-0x20]
   140008dc9:	0f b7 45 e8          	movzx  eax,WORD PTR [rbp-0x18]
   140008dcd:	98                   	cwde
   140008dce:	01 c0                	add    eax,eax
   140008dd0:	25 ff ff 00 00       	and    eax,0xffff
   140008dd5:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008dd8:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140008ddb:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
   140008dde:	81 e2 ff ff ff 7f    	and    edx,0x7fffffff
   140008de4:	09 d0                	or     eax,edx
   140008de6:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140008de9:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140008dec:	f7 d8                	neg    eax
   140008dee:	0b 45 f8             	or     eax,DWORD PTR [rbp-0x8]
   140008df1:	c1 e8 1f             	shr    eax,0x1f
   140008df4:	89 c2                	mov    edx,eax
   140008df6:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008df9:	09 d0                	or     eax,edx
   140008dfb:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008dfe:	b8 fe ff 00 00       	mov    eax,0xfffe
   140008e03:	2b 45 fc             	sub    eax,DWORD PTR [rbp-0x4]
   140008e06:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140008e09:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140008e0c:	c1 f8 10             	sar    eax,0x10
   140008e0f:	48 83 c4 38          	add    rsp,0x38
   140008e13:	5b                   	pop    rbx
   140008e14:	5d                   	pop    rbp
   140008e15:	c3                   	ret
   140008e16:	90                   	nop
   140008e17:	90                   	nop
   140008e18:	90                   	nop
   140008e19:	90                   	nop
   140008e1a:	90                   	nop
   140008e1b:	90                   	nop
   140008e1c:	90                   	nop
   140008e1d:	90                   	nop
   140008e1e:	90                   	nop
   140008e1f:	90                   	nop

0000000140008e20 <wcsnlen>:
   140008e20:	55                   	push   rbp
   140008e21:	48 89 e5             	mov    rbp,rsp
   140008e24:	48 83 ec 10          	sub    rsp,0x10
   140008e28:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e2c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e30:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   140008e37:	00 
   140008e38:	eb 0a                	jmp    140008e44 <wcsnlen+0x24>
   140008e3a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e3f:	48 83 45 10 02       	add    QWORD PTR [rbp+0x10],0x2
   140008e44:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e48:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e4c:	73 0c                	jae    140008e5a <wcsnlen+0x3a>
   140008e4e:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e52:	0f b7 00             	movzx  eax,WORD PTR [rax]
   140008e55:	66 85 c0             	test   ax,ax
   140008e58:	75 e0                	jne    140008e3a <wcsnlen+0x1a>
   140008e5a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e5e:	48 83 c4 10          	add    rsp,0x10
   140008e62:	5d                   	pop    rbp
   140008e63:	c3                   	ret
   140008e64:	90                   	nop
   140008e65:	90                   	nop
   140008e66:	90                   	nop
   140008e67:	90                   	nop
   140008e68:	90                   	nop
   140008e69:	90                   	nop
   140008e6a:	90                   	nop
   140008e6b:	90                   	nop
   140008e6c:	90                   	nop
   140008e6d:	90                   	nop
   140008e6e:	90                   	nop
   140008e6f:	90                   	nop

0000000140008e70 <strnlen>:
   140008e70:	55                   	push   rbp
   140008e71:	48 89 e5             	mov    rbp,rsp
   140008e74:	48 83 ec 10          	sub    rsp,0x10
   140008e78:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008e7c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008e80:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008e84:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008e88:	eb 05                	jmp    140008e8f <strnlen+0x1f>
   140008e8a:	48 83 45 f8 01       	add    QWORD PTR [rbp-0x8],0x1
   140008e8f:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008e93:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008e97:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008e9b:	73 0b                	jae    140008ea8 <strnlen+0x38>
   140008e9d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ea1:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140008ea4:	84 c0                	test   al,al
   140008ea6:	75 e2                	jne    140008e8a <strnlen+0x1a>
   140008ea8:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eac:	48 2b 45 10          	sub    rax,QWORD PTR [rbp+0x10]
   140008eb0:	48 83 c4 10          	add    rsp,0x10
   140008eb4:	5d                   	pop    rbp
   140008eb5:	c3                   	ret
   140008eb6:	90                   	nop
   140008eb7:	90                   	nop
   140008eb8:	90                   	nop
   140008eb9:	90                   	nop
   140008eba:	90                   	nop
   140008ebb:	90                   	nop
   140008ebc:	90                   	nop
   140008ebd:	90                   	nop
   140008ebe:	90                   	nop
   140008ebf:	90                   	nop

0000000140008ec0 <_initterm_e>:
   140008ec0:	55                   	push   rbp
   140008ec1:	48 89 e5             	mov    rbp,rsp
   140008ec4:	48 83 ec 30          	sub    rsp,0x30
   140008ec8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008ecc:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140008ed0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008ed4:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140008ed8:	eb 29                	jmp    140008f03 <_initterm_e+0x43>
   140008eda:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008ede:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008ee1:	48 85 c0             	test   rax,rax
   140008ee4:	74 17                	je     140008efd <_initterm_e+0x3d>
   140008ee6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008eea:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008eed:	ff d0                	call   rax
   140008eef:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   140008ef2:	83 7d f4 00          	cmp    DWORD PTR [rbp-0xc],0x0
   140008ef6:	74 06                	je     140008efe <_initterm_e+0x3e>
   140008ef8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
   140008efb:	eb 15                	jmp    140008f12 <_initterm_e+0x52>
   140008efd:	90                   	nop
   140008efe:	48 83 45 f8 08       	add    QWORD PTR [rbp-0x8],0x8
   140008f03:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140008f07:	48 3b 45 18          	cmp    rax,QWORD PTR [rbp+0x18]
   140008f0b:	72 cd                	jb     140008eda <_initterm_e+0x1a>
   140008f0d:	b8 00 00 00 00       	mov    eax,0x0
   140008f12:	48 83 c4 30          	add    rsp,0x30
   140008f16:	5d                   	pop    rbp
   140008f17:	c3                   	ret
   140008f18:	90                   	nop
   140008f19:	90                   	nop
   140008f1a:	90                   	nop
   140008f1b:	90                   	nop
   140008f1c:	90                   	nop
   140008f1d:	90                   	nop
   140008f1e:	90                   	nop
   140008f1f:	90                   	nop

0000000140008f20 <__p__fmode>:
   140008f20:	55                   	push   rbp
   140008f21:	48 89 e5             	mov    rbp,rsp
   140008f24:	48 8b 05 f5 26 00 00 	mov    rax,QWORD PTR [rip+0x26f5]        # 14000b620 <.refptr.__imp__fmode>
   140008f2b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f2e:	5d                   	pop    rbp
   140008f2f:	c3                   	ret

0000000140008f30 <__p__commode>:
   140008f30:	55                   	push   rbp
   140008f31:	48 89 e5             	mov    rbp,rsp
   140008f34:	48 8b 05 d5 26 00 00 	mov    rax,QWORD PTR [rip+0x26d5]        # 14000b610 <.refptr.__imp__commode>
   140008f3b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f3e:	5d                   	pop    rbp
   140008f3f:	c3                   	ret

0000000140008f40 <__p___initenv>:
   140008f40:	55                   	push   rbp
   140008f41:	48 89 e5             	mov    rbp,rsp
   140008f44:	48 8b 05 b5 26 00 00 	mov    rax,QWORD PTR [rip+0x26b5]        # 14000b600 <.refptr.__imp___initenv>
   140008f4b:	48 8b 00             	mov    rax,QWORD PTR [rax]
   140008f4e:	5d                   	pop    rbp
   140008f4f:	c3                   	ret

0000000140008f50 <_lock_file>:
   140008f50:	55                   	push   rbp
   140008f51:	48 89 e5             	mov    rbp,rsp
   140008f54:	48 83 ec 20          	sub    rsp,0x20
   140008f58:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008f5c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f61:	e8 6a 01 00 00       	call   1400090d0 <__acrt_iob_func>
   140008f66:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008f6a:	72 52                	jb     140008fbe <_lock_file+0x6e>
   140008f6c:	b9 13 00 00 00       	mov    ecx,0x13
   140008f71:	e8 5a 01 00 00       	call   1400090d0 <__acrt_iob_func>
   140008f76:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140008f7a:	72 42                	jb     140008fbe <_lock_file+0x6e>
   140008f7c:	b9 00 00 00 00       	mov    ecx,0x0
   140008f81:	e8 4a 01 00 00       	call   1400090d0 <__acrt_iob_func>
   140008f86:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140008f8a:	48 29 c2             	sub    rdx,rax
   140008f8d:	48 c1 fa 04          	sar    rdx,0x4
   140008f91:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140008f98:	aa aa aa 
   140008f9b:	48 0f af c2          	imul   rax,rdx
   140008f9f:	83 c0 10             	add    eax,0x10
   140008fa2:	89 c1                	mov    ecx,eax
   140008fa4:	e8 1f 07 00 00       	call   1400096c8 <_lock>
   140008fa9:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fad:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   140008fb0:	80 cc 80             	or     ah,0x80
   140008fb3:	89 c2                	mov    edx,eax
   140008fb5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fb9:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140008fbc:	eb 15                	jmp    140008fd3 <_lock_file+0x83>
   140008fbe:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140008fc2:	48 83 c0 30          	add    rax,0x30
   140008fc6:	48 89 c1             	mov    rcx,rax
   140008fc9:	48 8b 05 30 72 00 00 	mov    rax,QWORD PTR [rip+0x7230]        # 140010200 <__imp_EnterCriticalSection>
   140008fd0:	ff d0                	call   rax
   140008fd2:	90                   	nop
   140008fd3:	90                   	nop
   140008fd4:	48 83 c4 20          	add    rsp,0x20
   140008fd8:	5d                   	pop    rbp
   140008fd9:	c3                   	ret

0000000140008fda <_unlock_file>:
   140008fda:	55                   	push   rbp
   140008fdb:	48 89 e5             	mov    rbp,rsp
   140008fde:	48 83 ec 20          	sub    rsp,0x20
   140008fe2:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   140008fe6:	b9 00 00 00 00       	mov    ecx,0x0
   140008feb:	e8 e0 00 00 00       	call   1400090d0 <__acrt_iob_func>
   140008ff0:	48 39 45 10          	cmp    QWORD PTR [rbp+0x10],rax
   140008ff4:	72 52                	jb     140009048 <_unlock_file+0x6e>
   140008ff6:	b9 13 00 00 00       	mov    ecx,0x13
   140008ffb:	e8 d0 00 00 00       	call   1400090d0 <__acrt_iob_func>
   140009000:	48 3b 45 10          	cmp    rax,QWORD PTR [rbp+0x10]
   140009004:	72 42                	jb     140009048 <_unlock_file+0x6e>
   140009006:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000900a:	8b 40 18             	mov    eax,DWORD PTR [rax+0x18]
   14000900d:	80 e4 7f             	and    ah,0x7f
   140009010:	89 c2                	mov    edx,eax
   140009012:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009016:	89 50 18             	mov    DWORD PTR [rax+0x18],edx
   140009019:	b9 00 00 00 00       	mov    ecx,0x0
   14000901e:	e8 ad 00 00 00       	call   1400090d0 <__acrt_iob_func>
   140009023:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
   140009027:	48 29 c2             	sub    rdx,rax
   14000902a:	48 c1 fa 04          	sar    rdx,0x4
   14000902e:	48 b8 ab aa aa aa aa 	movabs rax,0xaaaaaaaaaaaaaaab
   140009035:	aa aa aa 
   140009038:	48 0f af c2          	imul   rax,rdx
   14000903c:	83 c0 10             	add    eax,0x10
   14000903f:	89 c1                	mov    ecx,eax
   140009041:	e8 8a 06 00 00       	call   1400096d0 <_unlock>
   140009046:	eb 15                	jmp    14000905d <_unlock_file+0x83>
   140009048:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000904c:	48 83 c0 30          	add    rax,0x30
   140009050:	48 89 c1             	mov    rcx,rax
   140009053:	48 8b 05 de 71 00 00 	mov    rax,QWORD PTR [rip+0x71de]        # 140010238 <__imp_LeaveCriticalSection>
   14000905a:	ff d0                	call   rax
   14000905c:	90                   	nop
   14000905d:	90                   	nop
   14000905e:	48 83 c4 20          	add    rsp,0x20
   140009062:	5d                   	pop    rbp
   140009063:	c3                   	ret
   140009064:	90                   	nop
   140009065:	90                   	nop
   140009066:	90                   	nop
   140009067:	90                   	nop
   140009068:	90                   	nop
   140009069:	90                   	nop
   14000906a:	90                   	nop
   14000906b:	90                   	nop
   14000906c:	90                   	nop
   14000906d:	90                   	nop
   14000906e:	90                   	nop
   14000906f:	90                   	nop

0000000140009070 <_set_invalid_parameter_handler>:
   140009070:	55                   	push   rbp
   140009071:	48 89 e5             	mov    rbp,rsp
   140009074:	48 83 ec 10          	sub    rsp,0x10
   140009078:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000907c:	48 8d 05 fd 6a 00 00 	lea    rax,[rip+0x6afd]        # 14000fb80 <handler>
   140009083:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   140009087:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000908b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   14000908f:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
   140009093:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   140009097:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000909a:	48 89 d0             	mov    rax,rdx
   14000909d:	48 83 c4 10          	add    rsp,0x10
   1400090a1:	5d                   	pop    rbp
   1400090a2:	c3                   	ret

00000001400090a3 <_get_invalid_parameter_handler>:
   1400090a3:	55                   	push   rbp
   1400090a4:	48 89 e5             	mov    rbp,rsp
   1400090a7:	48 8b 05 d2 6a 00 00 	mov    rax,QWORD PTR [rip+0x6ad2]        # 14000fb80 <handler>
   1400090ae:	5d                   	pop    rbp
   1400090af:	c3                   	ret

00000001400090b0 <_configthreadlocale>:
   1400090b0:	55                   	push   rbp
   1400090b1:	48 89 e5             	mov    rbp,rsp
   1400090b4:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400090b7:	83 7d 10 01          	cmp    DWORD PTR [rbp+0x10],0x1
   1400090bb:	75 07                	jne    1400090c4 <_configthreadlocale+0x14>
   1400090bd:	b8 ff ff ff ff       	mov    eax,0xffffffff
   1400090c2:	eb 05                	jmp    1400090c9 <_configthreadlocale+0x19>
   1400090c4:	b8 02 00 00 00       	mov    eax,0x2
   1400090c9:	5d                   	pop    rbp
   1400090ca:	c3                   	ret
   1400090cb:	90                   	nop
   1400090cc:	90                   	nop
   1400090cd:	90                   	nop
   1400090ce:	90                   	nop
   1400090cf:	90                   	nop

00000001400090d0 <__acrt_iob_func>:
   1400090d0:	55                   	push   rbp
   1400090d1:	48 89 e5             	mov    rbp,rsp
   1400090d4:	48 83 ec 20          	sub    rsp,0x20
   1400090d8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400090db:	e8 b0 05 00 00       	call   140009690 <__iob_func>
   1400090e0:	48 89 c1             	mov    rcx,rax
   1400090e3:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
   1400090e6:	48 89 d0             	mov    rax,rdx
   1400090e9:	48 01 c0             	add    rax,rax
   1400090ec:	48 01 d0             	add    rax,rdx
   1400090ef:	48 c1 e0 04          	shl    rax,0x4
   1400090f3:	48 01 c8             	add    rax,rcx
   1400090f6:	48 83 c4 20          	add    rsp,0x20
   1400090fa:	5d                   	pop    rbp
   1400090fb:	c3                   	ret
   1400090fc:	90                   	nop
   1400090fd:	90                   	nop
   1400090fe:	90                   	nop
   1400090ff:	90                   	nop

0000000140009100 <wcrtomb>:
   140009100:	55                   	push   rbp
   140009101:	48 89 e5             	mov    rbp,rsp
   140009104:	48 83 ec 40          	sub    rsp,0x40
   140009108:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000910c:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   140009110:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009114:	e8 5f 05 00 00       	call   140009678 <___lc_codepage_func>
   140009119:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   14000911c:	e8 5f 05 00 00       	call   140009680 <___mb_cur_max_func>
   140009121:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   140009124:	44 8b 4d fc          	mov    r9d,DWORD PTR [rbp-0x4]
   140009128:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   14000912c:	0f b7 55 18          	movzx  edx,WORD PTR [rbp+0x18]
   140009130:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009134:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   140009137:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   14000913b:	48 89 c1             	mov    rcx,rax
   14000913e:	e8 7d 00 00 00       	call   1400091c0 <__mingw_wcrtomb_cp>
   140009143:	48 83 c4 40          	add    rsp,0x40
   140009147:	5d                   	pop    rbp
   140009148:	c3                   	ret
   140009149:	90                   	nop
   14000914a:	90                   	nop
   14000914b:	90                   	nop
   14000914c:	90                   	nop
   14000914d:	90                   	nop
   14000914e:	90                   	nop
   14000914f:	90                   	nop

0000000140009150 <mbrtowc>:
   140009150:	55                   	push   rbp
   140009151:	48 89 e5             	mov    rbp,rsp
   140009154:	48 83 ec 40          	sub    rsp,0x40
   140009158:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000915c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009160:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009164:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009168:	48 83 7d 28 00       	cmp    QWORD PTR [rbp+0x28],0x0
   14000916d:	75 0b                	jne    14000917a <mbrtowc+0x2a>
   14000916f:	48 8d 05 1a 6a 00 00 	lea    rax,[rip+0x6a1a]        # 14000fb90 <state_mbrtowc.0>
   140009176:	48 89 45 28          	mov    QWORD PTR [rbp+0x28],rax
   14000917a:	e8 f9 04 00 00       	call   140009678 <___lc_codepage_func>
   14000917f:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   140009182:	e8 f9 04 00 00       	call   140009680 <___mb_cur_max_func>
   140009187:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
   14000918a:	4c 8b 4d 28          	mov    r9,QWORD PTR [rbp+0x28]
   14000918e:	4c 8b 45 20          	mov    r8,QWORD PTR [rbp+0x20]
   140009192:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
   140009196:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   14000919a:	8b 4d f8             	mov    ecx,DWORD PTR [rbp-0x8]
   14000919d:	89 4c 24 28          	mov    DWORD PTR [rsp+0x28],ecx
   1400091a1:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
   1400091a4:	89 4c 24 20          	mov    DWORD PTR [rsp+0x20],ecx
   1400091a8:	48 89 c1             	mov    rcx,rax
   1400091ab:	e8 70 01 00 00       	call   140009320 <__mingw_mbrtowc_cp>
   1400091b0:	48 83 c4 40          	add    rsp,0x40
   1400091b4:	5d                   	pop    rbp
   1400091b5:	c3                   	ret
   1400091b6:	90                   	nop
   1400091b7:	90                   	nop
   1400091b8:	90                   	nop
   1400091b9:	90                   	nop
   1400091ba:	90                   	nop
   1400091bb:	90                   	nop
   1400091bc:	90                   	nop
   1400091bd:	90                   	nop
   1400091be:	90                   	nop
   1400091bf:	90                   	nop

00000001400091c0 <__mingw_wcrtomb_cp>:
   1400091c0:	55                   	push   rbp
   1400091c1:	48 89 e5             	mov    rbp,rsp
   1400091c4:	48 83 ec 50          	sub    rsp,0x50
   1400091c8:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   1400091cc:	66 89 55 18          	mov    WORD PTR [rbp+0x18],dx
   1400091d0:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   1400091d4:	44 89 4d 28          	mov    DWORD PTR [rbp+0x28],r9d
   1400091d8:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400091dd:	75 1b                	jne    1400091fa <__mingw_wcrtomb_cp+0x3a>
   1400091df:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091e4:	74 0a                	je     1400091f0 <__mingw_wcrtomb_cp+0x30>
   1400091e6:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   1400091ea:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   1400091f0:	b8 01 00 00 00       	mov    eax,0x1
   1400091f5:	e9 17 01 00 00       	jmp    140009311 <__mingw_wcrtomb_cp+0x151>
   1400091fa:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   1400091ff:	74 21                	je     140009222 <__mingw_wcrtomb_cp+0x62>
   140009201:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
   140009205:	8b 00                	mov    eax,DWORD PTR [rax]
   140009207:	85 c0                	test   eax,eax
   140009209:	74 17                	je     140009222 <__mingw_wcrtomb_cp+0x62>
   14000920b:	e8 a8 04 00 00       	call   1400096b8 <_errno>
   140009210:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009216:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000921d:	e9 ef 00 00 00       	jmp    140009311 <__mingw_wcrtomb_cp+0x151>
   140009222:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009226:	66 85 c0             	test   ax,ax
   140009229:	75 18                	jne    140009243 <__mingw_wcrtomb_cp+0x83>
   14000922b:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   140009230:	74 07                	je     140009239 <__mingw_wcrtomb_cp+0x79>
   140009232:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009236:	c6 00 00             	mov    BYTE PTR [rax],0x0
   140009239:	b8 01 00 00 00       	mov    eax,0x1
   14000923e:	e9 ce 00 00 00       	jmp    140009311 <__mingw_wcrtomb_cp+0x151>
   140009243:	83 7d 28 00          	cmp    DWORD PTR [rbp+0x28],0x0
   140009247:	75 2b                	jne    140009274 <__mingw_wcrtomb_cp+0xb4>
   140009249:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   14000924d:	66 3d ff 00          	cmp    ax,0xff
   140009251:	0f 87 a4 00 00 00    	ja     1400092fb <__mingw_wcrtomb_cp+0x13b>
   140009257:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000925c:	74 0c                	je     14000926a <__mingw_wcrtomb_cp+0xaa>
   14000925e:	0f b7 45 18          	movzx  eax,WORD PTR [rbp+0x18]
   140009262:	89 c2                	mov    edx,eax
   140009264:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009268:	88 10                	mov    BYTE PTR [rax],dl
   14000926a:	b8 01 00 00 00       	mov    eax,0x1
   14000926f:	e9 9d 00 00 00       	jmp    140009311 <__mingw_wcrtomb_cp+0x151>
   140009274:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   14000927b:	66 c7 45 f6 00 00    	mov    WORD PTR [rbp-0xa],0x0
   140009281:	48 8d 4d 18          	lea    rcx,[rbp+0x18]
   140009285:	8b 45 28             	mov    eax,DWORD PTR [rbp+0x28]
   140009288:	48 8d 55 f8          	lea    rdx,[rbp-0x8]
   14000928c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
   140009291:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
   140009298:	00 00 
   14000929a:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000929d:	89 54 24 28          	mov    DWORD PTR [rsp+0x28],edx
   1400092a1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400092a5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400092aa:	41 b9 01 00 00 00    	mov    r9d,0x1
   1400092b0:	49 89 c8             	mov    r8,rcx
   1400092b3:	ba 00 00 00 00       	mov    edx,0x0
   1400092b8:	89 c1                	mov    ecx,eax
   1400092ba:	48 8b 05 b7 6f 00 00 	mov    rax,QWORD PTR [rip+0x6fb7]        # 140010278 <__imp_WideCharToMultiByte>
   1400092c1:	ff d0                	call   rax
   1400092c3:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
   1400092c6:	83 7d fc 00          	cmp    DWORD PTR [rbp-0x4],0x0
   1400092ca:	74 32                	je     1400092fe <__mingw_wcrtomb_cp+0x13e>
   1400092cc:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092cf:	3b 45 30             	cmp    eax,DWORD PTR [rbp+0x30]
   1400092d2:	7f 2a                	jg     1400092fe <__mingw_wcrtomb_cp+0x13e>
   1400092d4:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   1400092d7:	85 c0                	test   eax,eax
   1400092d9:	75 23                	jne    1400092fe <__mingw_wcrtomb_cp+0x13e>
   1400092db:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092de:	48 63 c8             	movsxd rcx,eax
   1400092e1:	48 8d 55 f6          	lea    rdx,[rbp-0xa]
   1400092e5:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400092e9:	49 89 c8             	mov    r8,rcx
   1400092ec:	48 89 c1             	mov    rcx,rax
   1400092ef:	e8 34 04 00 00       	call   140009728 <memcpy>
   1400092f4:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400092f7:	48 98                	cdqe
   1400092f9:	eb 16                	jmp    140009311 <__mingw_wcrtomb_cp+0x151>
   1400092fb:	90                   	nop
   1400092fc:	eb 01                	jmp    1400092ff <__mingw_wcrtomb_cp+0x13f>
   1400092fe:	90                   	nop
   1400092ff:	e8 b4 03 00 00       	call   1400096b8 <_errno>
   140009304:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000930a:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009311:	48 83 c4 50          	add    rsp,0x50
   140009315:	5d                   	pop    rbp
   140009316:	c3                   	ret
   140009317:	90                   	nop
   140009318:	90                   	nop
   140009319:	90                   	nop
   14000931a:	90                   	nop
   14000931b:	90                   	nop
   14000931c:	90                   	nop
   14000931d:	90                   	nop
   14000931e:	90                   	nop
   14000931f:	90                   	nop

0000000140009320 <__mingw_mbrtowc_cp>:
   140009320:	55                   	push   rbp
   140009321:	48 89 e5             	mov    rbp,rsp
   140009324:	48 83 ec 50          	sub    rsp,0x50
   140009328:	48 89 4d 10          	mov    QWORD PTR [rbp+0x10],rcx
   14000932c:	48 89 55 18          	mov    QWORD PTR [rbp+0x18],rdx
   140009330:	4c 89 45 20          	mov    QWORD PTR [rbp+0x20],r8
   140009334:	4c 89 4d 28          	mov    QWORD PTR [rbp+0x28],r9
   140009338:	48 83 7d 18 00       	cmp    QWORD PTR [rbp+0x18],0x0
   14000933d:	75 1b                	jne    14000935a <__mingw_mbrtowc_cp+0x3a>
   14000933f:	48 c7 45 10 00 00 00 	mov    QWORD PTR [rbp+0x10],0x0
   140009346:	00 
   140009347:	48 8d 05 f2 21 00 00 	lea    rax,[rip+0x21f2]        # 14000b540 <.rdata>
   14000934e:	48 89 45 18          	mov    QWORD PTR [rbp+0x18],rax
   140009352:	48 c7 45 20 01 00 00 	mov    QWORD PTR [rbp+0x20],0x1
   140009359:	00 
   14000935a:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000935e:	8b 00                	mov    eax,DWORD PTR [rax]
   140009360:	3d ff 00 00 00       	cmp    eax,0xff
   140009365:	0f 87 b9 01 00 00    	ja     140009524 <__mingw_mbrtowc_cp+0x204>
   14000936b:	48 83 7d 20 00       	cmp    QWORD PTR [rbp+0x20],0x0
   140009370:	75 0c                	jne    14000937e <__mingw_mbrtowc_cp+0x5e>
   140009372:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   140009379:	e9 bc 01 00 00       	jmp    14000953a <__mingw_mbrtowc_cp+0x21a>
   14000937e:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009382:	8b 00                	mov    eax,DWORD PTR [rax]
   140009384:	89 45 f0             	mov    DWORD PTR [rbp-0x10],eax
   140009387:	83 7d 38 01          	cmp    DWORD PTR [rbp+0x38],0x1
   14000938b:	75 0c                	jne    140009399 <__mingw_mbrtowc_cp+0x79>
   14000938d:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009391:	84 c0                	test   al,al
   140009393:	0f 85 8e 01 00 00    	jne    140009527 <__mingw_mbrtowc_cp+0x207>
   140009399:	83 7d 30 00          	cmp    DWORD PTR [rbp+0x30],0x0
   14000939d:	75 2c                	jne    1400093cb <__mingw_mbrtowc_cp+0xab>
   14000939f:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400093a4:	74 11                	je     1400093b7 <__mingw_mbrtowc_cp+0x97>
   1400093a6:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093aa:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093ad:	0f b6 d0             	movzx  edx,al
   1400093b0:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400093b4:	66 89 10             	mov    WORD PTR [rax],dx
   1400093b7:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093bb:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093be:	84 c0                	test   al,al
   1400093c0:	0f 95 c0             	setne  al
   1400093c3:	0f b6 c0             	movzx  eax,al
   1400093c6:	e9 6f 01 00 00       	jmp    14000953a <__mingw_mbrtowc_cp+0x21a>
   1400093cb:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
   1400093d2:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
   1400093d9:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   1400093dd:	84 c0                	test   al,al
   1400093df:	74 1a                	je     1400093fb <__mingw_mbrtowc_cp+0xdb>
   1400093e1:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   1400093e5:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   1400093e8:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   1400093eb:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   1400093f2:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   1400093f9:	eb 73                	jmp    14000946e <__mingw_mbrtowc_cp+0x14e>
   1400093fb:	83 7d 38 02          	cmp    DWORD PTR [rbp+0x38],0x2
   1400093ff:	75 5c                	jne    14000945d <__mingw_mbrtowc_cp+0x13d>
   140009401:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009405:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009408:	0f b6 c0             	movzx  eax,al
   14000940b:	8b 55 30             	mov    edx,DWORD PTR [rbp+0x30]
   14000940e:	89 c1                	mov    ecx,eax
   140009410:	e8 ab 01 00 00       	call   1400095c0 <__mingw_isleadbyte_cp>
   140009415:	85 c0                	test   eax,eax
   140009417:	74 44                	je     14000945d <__mingw_mbrtowc_cp+0x13d>
   140009419:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   14000941d:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009420:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009423:	48 83 7d 20 01       	cmp    QWORD PTR [rbp+0x20],0x1
   140009428:	77 15                	ja     14000943f <__mingw_mbrtowc_cp+0x11f>
   14000942a:	8b 55 f0             	mov    edx,DWORD PTR [rbp-0x10]
   14000942d:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   140009431:	89 10                	mov    DWORD PTR [rax],edx
   140009433:	48 c7 c0 fe ff ff ff 	mov    rax,0xfffffffffffffffe
   14000943a:	e9 fb 00 00 00       	jmp    14000953a <__mingw_mbrtowc_cp+0x21a>
   14000943f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009443:	48 83 c0 01          	add    rax,0x1
   140009447:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   14000944a:	88 45 f1             	mov    BYTE PTR [rbp-0xf],al
   14000944d:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [rbp-0x8],0x2
   140009454:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [rbp-0x4],0x2
   14000945b:	eb 11                	jmp    14000946e <__mingw_mbrtowc_cp+0x14e>
   14000945d:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
   140009461:	0f b6 00             	movzx  eax,BYTE PTR [rax]
   140009464:	88 45 f0             	mov    BYTE PTR [rbp-0x10],al
   140009467:	c7 45 f8 01 00 00 00 	mov    DWORD PTR [rbp-0x8],0x1
   14000946e:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
   140009472:	84 c0                	test   al,al
   140009474:	75 24                	jne    14000949a <__mingw_mbrtowc_cp+0x17a>
   140009476:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   14000947b:	74 09                	je     140009486 <__mingw_mbrtowc_cp+0x166>
   14000947d:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   140009481:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
   140009486:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   14000948a:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009490:	b8 00 00 00 00       	mov    eax,0x0
   140009495:	e9 a0 00 00 00       	jmp    14000953a <__mingw_mbrtowc_cp+0x21a>
   14000949a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
   14000949e:	75 08                	jne    1400094a8 <__mingw_mbrtowc_cp+0x188>
   1400094a0:	0f b6 45 f1          	movzx  eax,BYTE PTR [rbp-0xf]
   1400094a4:	84 c0                	test   al,al
   1400094a6:	74 64                	je     14000950c <__mingw_mbrtowc_cp+0x1ec>
   1400094a8:	66 c7 45 ee ff ff    	mov    WORD PTR [rbp-0x12],0xffff
   1400094ae:	44 8b 45 fc          	mov    r8d,DWORD PTR [rbp-0x4]
   1400094b2:	48 8d 4d f0          	lea    rcx,[rbp-0x10]
   1400094b6:	8b 45 30             	mov    eax,DWORD PTR [rbp+0x30]
   1400094b9:	c7 44 24 28 01 00 00 	mov    DWORD PTR [rsp+0x28],0x1
   1400094c0:	00 
   1400094c1:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
   1400094c5:	48 89 54 24 20       	mov    QWORD PTR [rsp+0x20],rdx
   1400094ca:	45 89 c1             	mov    r9d,r8d
   1400094cd:	49 89 c8             	mov    r8,rcx
   1400094d0:	ba 08 00 00 00       	mov    edx,0x8
   1400094d5:	89 c1                	mov    ecx,eax
   1400094d7:	48 8b 05 6a 6d 00 00 	mov    rax,QWORD PTR [rip+0x6d6a]        # 140010248 <__imp_MultiByteToWideChar>
   1400094de:	ff d0                	call   rax
   1400094e0:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
   1400094e3:	83 7d f4 01          	cmp    DWORD PTR [rbp-0xc],0x1
   1400094e7:	75 26                	jne    14000950f <__mingw_mbrtowc_cp+0x1ef>
   1400094e9:	48 83 7d 10 00       	cmp    QWORD PTR [rbp+0x10],0x0
   1400094ee:	74 0b                	je     1400094fb <__mingw_mbrtowc_cp+0x1db>
   1400094f0:	0f b7 55 ee          	movzx  edx,WORD PTR [rbp-0x12]
   1400094f4:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
   1400094f8:	66 89 10             	mov    WORD PTR [rax],dx
   1400094fb:	48 8b 45 28          	mov    rax,QWORD PTR [rbp+0x28]
   1400094ff:	c7 00 00 00 00 00    	mov    DWORD PTR [rax],0x0
   140009505:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
   140009508:	48 98                	cdqe
   14000950a:	eb 2e                	jmp    14000953a <__mingw_mbrtowc_cp+0x21a>
   14000950c:	90                   	nop
   14000950d:	eb 01                	jmp    140009510 <__mingw_mbrtowc_cp+0x1f0>
   14000950f:	90                   	nop
   140009510:	e8 a3 01 00 00       	call   1400096b8 <_errno>
   140009515:	c7 00 2a 00 00 00    	mov    DWORD PTR [rax],0x2a
   14000951b:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   140009522:	eb 16                	jmp    14000953a <__mingw_mbrtowc_cp+0x21a>
   140009524:	90                   	nop
   140009525:	eb 01                	jmp    140009528 <__mingw_mbrtowc_cp+0x208>
   140009527:	90                   	nop
   140009528:	e8 8b 01 00 00       	call   1400096b8 <_errno>
   14000952d:	c7 00 16 00 00 00    	mov    DWORD PTR [rax],0x16
   140009533:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
   14000953a:	48 83 c4 50          	add    rsp,0x50
   14000953e:	5d                   	pop    rbp
   14000953f:	c3                   	ret

0000000140009540 <fallback_IsDBCSLeadByteEx>:
   140009540:	55                   	push   rbp
   140009541:	48 89 e5             	mov    rbp,rsp
   140009544:	48 83 ec 40          	sub    rsp,0x40
   140009548:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   14000954b:	88 55 18             	mov    BYTE PTR [rbp+0x18],dl
   14000954e:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
   140009552:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009555:	89 c1                	mov    ecx,eax
   140009557:	48 8b 05 b2 6c 00 00 	mov    rax,QWORD PTR [rip+0x6cb2]        # 140010210 <__imp_GetCPInfo>
   14000955e:	ff d0                	call   rax
   140009560:	85 c0                	test   eax,eax
   140009562:	74 51                	je     1400095b5 <fallback_IsDBCSLeadByteEx+0x75>
   140009564:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
   140009567:	83 f8 02             	cmp    eax,0x2
   14000956a:	75 49                	jne    1400095b5 <fallback_IsDBCSLeadByteEx+0x75>
   14000956c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
   140009573:	eb 2c                	jmp    1400095a1 <fallback_IsDBCSLeadByteEx+0x61>
   140009575:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009578:	48 98                	cdqe
   14000957a:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   14000957f:	38 45 18             	cmp    BYTE PTR [rbp+0x18],al
   140009582:	72 19                	jb     14000959d <fallback_IsDBCSLeadByteEx+0x5d>
   140009584:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   140009587:	83 c0 01             	add    eax,0x1
   14000958a:	48 98                	cdqe
   14000958c:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   140009591:	3a 45 18             	cmp    al,BYTE PTR [rbp+0x18]
   140009594:	72 07                	jb     14000959d <fallback_IsDBCSLeadByteEx+0x5d>
   140009596:	b8 01 00 00 00       	mov    eax,0x1
   14000959b:	eb 1d                	jmp    1400095ba <fallback_IsDBCSLeadByteEx+0x7a>
   14000959d:	83 45 fc 02          	add    DWORD PTR [rbp-0x4],0x2
   1400095a1:	83 7d fc 0b          	cmp    DWORD PTR [rbp-0x4],0xb
   1400095a5:	7f 0e                	jg     1400095b5 <fallback_IsDBCSLeadByteEx+0x75>
   1400095a7:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
   1400095aa:	48 98                	cdqe
   1400095ac:	0f b6 44 05 e6       	movzx  eax,BYTE PTR [rbp+rax*1-0x1a]
   1400095b1:	84 c0                	test   al,al
   1400095b3:	75 c0                	jne    140009575 <fallback_IsDBCSLeadByteEx+0x35>
   1400095b5:	b8 00 00 00 00       	mov    eax,0x0
   1400095ba:	48 83 c4 40          	add    rsp,0x40
   1400095be:	5d                   	pop    rbp
   1400095bf:	c3                   	ret

00000001400095c0 <__mingw_isleadbyte_cp>:
   1400095c0:	55                   	push   rbp
   1400095c1:	48 89 e5             	mov    rbp,rsp
   1400095c4:	48 83 ec 40          	sub    rsp,0x40
   1400095c8:	89 4d 10             	mov    DWORD PTR [rbp+0x10],ecx
   1400095cb:	89 55 18             	mov    DWORD PTR [rbp+0x18],edx
   1400095ce:	48 8b 05 cb 65 00 00 	mov    rax,QWORD PTR [rip+0x65cb]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   1400095d5:	48 85 c0             	test   rax,rax
   1400095d8:	75 71                	jne    14000964b <__mingw_isleadbyte_cp+0x8b>
   1400095da:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
   1400095e1:	00 
   1400095e2:	48 8d 05 67 1f 00 00 	lea    rax,[rip+0x1f67]        # 14000b550 <.rdata>
   1400095e9:	48 89 c1             	mov    rcx,rax
   1400095ec:	48 8b 05 2d 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c2d]        # 140010220 <__imp_GetModuleHandleA>
   1400095f3:	ff d0                	call   rax
   1400095f5:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
   1400095f9:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
   1400095fe:	74 1b                	je     14000961b <__mingw_isleadbyte_cp+0x5b>
   140009600:	48 8d 15 56 1f 00 00 	lea    rdx,[rip+0x1f56]        # 14000b55d <.rdata+0xd>
   140009607:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
   14000960b:	48 89 c1             	mov    rcx,rax
   14000960e:	48 8b 05 13 6c 00 00 	mov    rax,QWORD PTR [rip+0x6c13]        # 140010228 <__imp_GetProcAddress>
   140009615:	ff d0                	call   rax
   140009617:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000961b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
   140009620:	75 0b                	jne    14000962d <__mingw_isleadbyte_cp+0x6d>
   140009622:	48 8d 05 17 ff ff ff 	lea    rax,[rip+0xffffffffffffff17]        # 140009540 <fallback_IsDBCSLeadByteEx>
   140009629:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
   14000962d:	48 8d 05 6c 65 00 00 	lea    rax,[rip+0x656c]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009634:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
   140009638:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
   14000963c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
   140009640:	48 8b 55 e0          	mov    rdx,QWORD PTR [rbp-0x20]
   140009644:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
   140009648:	48 87 10             	xchg   QWORD PTR [rax],rdx
   14000964b:	4c 8b 05 4e 65 00 00 	mov    r8,QWORD PTR [rip+0x654e]        # 14000fba0 <call_IsDBCSLeadByteEx.0>
   140009652:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
   140009655:	0f b6 d0             	movzx  edx,al
   140009658:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18]
   14000965b:	89 c1                	mov    ecx,eax
   14000965d:	41 ff d0             	call   r8
   140009660:	48 83 c4 40          	add    rsp,0x40
   140009664:	5d                   	pop    rbp
   140009665:	c3                   	ret
   140009666:	90                   	nop
   140009667:	90                   	nop
   140009668:	90                   	nop
   140009669:	90                   	nop
   14000966a:	90                   	nop
   14000966b:	90                   	nop
   14000966c:	90                   	nop
   14000966d:	90                   	nop
   14000966e:	90                   	nop
   14000966f:	90                   	nop

0000000140009670 <__C_specific_handler>:
   140009670:	ff 25 12 6c 00 00    	jmp    QWORD PTR [rip+0x6c12]        # 140010288 <__imp___C_specific_handler>
   140009676:	90                   	nop
   140009677:	90                   	nop

0000000140009678 <___lc_codepage_func>:
   140009678:	ff 25 12 6c 00 00    	jmp    QWORD PTR [rip+0x6c12]        # 140010290 <__imp____lc_codepage_func>
   14000967e:	90                   	nop
   14000967f:	90                   	nop

0000000140009680 <___mb_cur_max_func>:
   140009680:	ff 25 12 6c 00 00    	jmp    QWORD PTR [rip+0x6c12]        # 140010298 <__imp____mb_cur_max_func>
   140009686:	90                   	nop
   140009687:	90                   	nop

0000000140009688 <__getmainargs>:
   140009688:	ff 25 12 6c 00 00    	jmp    QWORD PTR [rip+0x6c12]        # 1400102a0 <__imp___getmainargs>
   14000968e:	90                   	nop
   14000968f:	90                   	nop

0000000140009690 <__iob_func>:
   140009690:	ff 25 1a 6c 00 00    	jmp    QWORD PTR [rip+0x6c1a]        # 1400102b0 <__imp___iob_func>
   140009696:	90                   	nop
   140009697:	90                   	nop

0000000140009698 <__set_app_type>:
   140009698:	ff 25 1a 6c 00 00    	jmp    QWORD PTR [rip+0x6c1a]        # 1400102b8 <__imp___set_app_type>
   14000969e:	90                   	nop
   14000969f:	90                   	nop

00000001400096a0 <__setusermatherr>:
   1400096a0:	ff 25 1a 6c 00 00    	jmp    QWORD PTR [rip+0x6c1a]        # 1400102c0 <__imp___setusermatherr>
   1400096a6:	90                   	nop
   1400096a7:	90                   	nop

00000001400096a8 <_amsg_exit>:
   1400096a8:	ff 25 1a 6c 00 00    	jmp    QWORD PTR [rip+0x6c1a]        # 1400102c8 <__imp__amsg_exit>
   1400096ae:	90                   	nop
   1400096af:	90                   	nop

00000001400096b0 <_cexit>:
   1400096b0:	ff 25 1a 6c 00 00    	jmp    QWORD PTR [rip+0x6c1a]        # 1400102d0 <__imp__cexit>
   1400096b6:	90                   	nop
   1400096b7:	90                   	nop

00000001400096b8 <_errno>:
   1400096b8:	ff 25 22 6c 00 00    	jmp    QWORD PTR [rip+0x6c22]        # 1400102e0 <__imp__errno>
   1400096be:	90                   	nop
   1400096bf:	90                   	nop

00000001400096c0 <_initterm>:
   1400096c0:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400102f0 <__imp__initterm>
   1400096c6:	90                   	nop
   1400096c7:	90                   	nop

00000001400096c8 <_lock>:
   1400096c8:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400102f8 <__imp__lock>
   1400096ce:	90                   	nop
   1400096cf:	90                   	nop

00000001400096d0 <_unlock>:
   1400096d0:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010300 <__imp__unlock>
   1400096d6:	90                   	nop
   1400096d7:	90                   	nop

00000001400096d8 <_crt_atexit>:
   1400096d8:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010308 <__imp__crt_atexit>
   1400096de:	90                   	nop
   1400096df:	90                   	nop

00000001400096e0 <abort>:
   1400096e0:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010310 <__imp_abort>
   1400096e6:	90                   	nop
   1400096e7:	90                   	nop

00000001400096e8 <calloc>:
   1400096e8:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010318 <__imp_calloc>
   1400096ee:	90                   	nop
   1400096ef:	90                   	nop

00000001400096f0 <exit>:
   1400096f0:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010320 <__imp_exit>
   1400096f6:	90                   	nop
   1400096f7:	90                   	nop

00000001400096f8 <fflush>:
   1400096f8:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010328 <__imp_fflush>
   1400096fe:	90                   	nop
   1400096ff:	90                   	nop

0000000140009700 <fprintf>:
   140009700:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010330 <__imp_fprintf>
   140009706:	90                   	nop
   140009707:	90                   	nop

0000000140009708 <fputc>:
   140009708:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010338 <__imp_fputc>
   14000970e:	90                   	nop
   14000970f:	90                   	nop

0000000140009710 <free>:
   140009710:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010340 <__imp_free>
   140009716:	90                   	nop
   140009717:	90                   	nop

0000000140009718 <localeconv>:
   140009718:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010348 <__imp_localeconv>
   14000971e:	90                   	nop
   14000971f:	90                   	nop

0000000140009720 <malloc>:
   140009720:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010350 <__imp_malloc>
   140009726:	90                   	nop
   140009727:	90                   	nop

0000000140009728 <memcpy>:
   140009728:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010358 <__imp_memcpy>
   14000972e:	90                   	nop
   14000972f:	90                   	nop

0000000140009730 <memset>:
   140009730:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010360 <__imp_memset>
   140009736:	90                   	nop
   140009737:	90                   	nop

0000000140009738 <puts>:
   140009738:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010368 <__imp_puts>
   14000973e:	90                   	nop
   14000973f:	90                   	nop

0000000140009740 <setvbuf>:
   140009740:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010370 <__imp_setvbuf>
   140009746:	90                   	nop
   140009747:	90                   	nop

0000000140009748 <signal>:
   140009748:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010378 <__imp_signal>
   14000974e:	90                   	nop
   14000974f:	90                   	nop

0000000140009750 <strerror>:
   140009750:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010380 <__imp_strerror>
   140009756:	90                   	nop
   140009757:	90                   	nop

0000000140009758 <strlen>:
   140009758:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010388 <__imp_strlen>
   14000975e:	90                   	nop
   14000975f:	90                   	nop

0000000140009760 <strncmp>:
   140009760:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010390 <__imp_strncmp>
   140009766:	90                   	nop
   140009767:	90                   	nop

0000000140009768 <vfprintf>:
   140009768:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 140010398 <__imp_vfprintf>
   14000976e:	90                   	nop
   14000976f:	90                   	nop

0000000140009770 <wcslen>:
   140009770:	ff 25 2a 6c 00 00    	jmp    QWORD PTR [rip+0x6c2a]        # 1400103a0 <__imp_wcslen>
   140009776:	90                   	nop
   140009777:	90                   	nop
   140009778:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000977f:	00 

0000000140009780 <WideCharToMultiByte>:
   140009780:	ff 25 f2 6a 00 00    	jmp    QWORD PTR [rip+0x6af2]        # 140010278 <__imp_WideCharToMultiByte>
   140009786:	90                   	nop
   140009787:	90                   	nop

0000000140009788 <VirtualQuery>:
   140009788:	ff 25 e2 6a 00 00    	jmp    QWORD PTR [rip+0x6ae2]        # 140010270 <__imp_VirtualQuery>
   14000978e:	90                   	nop
   14000978f:	90                   	nop

0000000140009790 <VirtualProtect>:
   140009790:	ff 25 d2 6a 00 00    	jmp    QWORD PTR [rip+0x6ad2]        # 140010268 <__imp_VirtualProtect>
   140009796:	90                   	nop
   140009797:	90                   	nop

0000000140009798 <TlsGetValue>:
   140009798:	ff 25 c2 6a 00 00    	jmp    QWORD PTR [rip+0x6ac2]        # 140010260 <__imp_TlsGetValue>
   14000979e:	90                   	nop
   14000979f:	90                   	nop

00000001400097a0 <Sleep>:
   1400097a0:	ff 25 b2 6a 00 00    	jmp    QWORD PTR [rip+0x6ab2]        # 140010258 <__imp_Sleep>
   1400097a6:	90                   	nop
   1400097a7:	90                   	nop

00000001400097a8 <SetUnhandledExceptionFilter>:
   1400097a8:	ff 25 a2 6a 00 00    	jmp    QWORD PTR [rip+0x6aa2]        # 140010250 <__imp_SetUnhandledExceptionFilter>
   1400097ae:	90                   	nop
   1400097af:	90                   	nop

00000001400097b0 <MultiByteToWideChar>:
   1400097b0:	ff 25 92 6a 00 00    	jmp    QWORD PTR [rip+0x6a92]        # 140010248 <__imp_MultiByteToWideChar>
   1400097b6:	90                   	nop
   1400097b7:	90                   	nop

00000001400097b8 <LoadLibraryA>:
   1400097b8:	ff 25 82 6a 00 00    	jmp    QWORD PTR [rip+0x6a82]        # 140010240 <__imp_LoadLibraryA>
   1400097be:	90                   	nop
   1400097bf:	90                   	nop

00000001400097c0 <LeaveCriticalSection>:
   1400097c0:	ff 25 72 6a 00 00    	jmp    QWORD PTR [rip+0x6a72]        # 140010238 <__imp_LeaveCriticalSection>
   1400097c6:	90                   	nop
   1400097c7:	90                   	nop

00000001400097c8 <InitializeCriticalSection>:
   1400097c8:	ff 25 62 6a 00 00    	jmp    QWORD PTR [rip+0x6a62]        # 140010230 <__imp_InitializeCriticalSection>
   1400097ce:	90                   	nop
   1400097cf:	90                   	nop

00000001400097d0 <GetProcAddress>:
   1400097d0:	ff 25 52 6a 00 00    	jmp    QWORD PTR [rip+0x6a52]        # 140010228 <__imp_GetProcAddress>
   1400097d6:	90                   	nop
   1400097d7:	90                   	nop

00000001400097d8 <GetModuleHandleA>:
   1400097d8:	ff 25 42 6a 00 00    	jmp    QWORD PTR [rip+0x6a42]        # 140010220 <__imp_GetModuleHandleA>
   1400097de:	90                   	nop
   1400097df:	90                   	nop

00000001400097e0 <GetLastError>:
   1400097e0:	ff 25 32 6a 00 00    	jmp    QWORD PTR [rip+0x6a32]        # 140010218 <__imp_GetLastError>
   1400097e6:	90                   	nop
   1400097e7:	90                   	nop

00000001400097e8 <GetCPInfo>:
   1400097e8:	ff 25 22 6a 00 00    	jmp    QWORD PTR [rip+0x6a22]        # 140010210 <__imp_GetCPInfo>
   1400097ee:	90                   	nop
   1400097ef:	90                   	nop

00000001400097f0 <FreeLibrary>:
   1400097f0:	ff 25 12 6a 00 00    	jmp    QWORD PTR [rip+0x6a12]        # 140010208 <__imp_FreeLibrary>
   1400097f6:	90                   	nop
   1400097f7:	90                   	nop

00000001400097f8 <EnterCriticalSection>:
   1400097f8:	ff 25 02 6a 00 00    	jmp    QWORD PTR [rip+0x6a02]        # 140010200 <__imp_EnterCriticalSection>
   1400097fe:	90                   	nop
   1400097ff:	90                   	nop

0000000140009800 <DeleteCriticalSection>:
   140009800:	ff 25 f2 69 00 00    	jmp    QWORD PTR [rip+0x69f2]        # 1400101f8 <__IAT_start__>
   140009806:	90                   	nop
   140009807:	90                   	nop
   140009808:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
   14000980f:	00 

0000000140009810 <register_frame_ctor>:
   140009810:	e9 5b 7e ff ff       	jmp    140001670 <__gcc_register_frame>
   140009815:	90                   	nop
   140009816:	90                   	nop
   140009817:	90                   	nop
   140009818:	90                   	nop
   140009819:	90                   	nop
   14000981a:	90                   	nop
   14000981b:	90                   	nop
   14000981c:	90                   	nop
   14000981d:	90                   	nop
   14000981e:	90                   	nop
   14000981f:	90                   	nop
