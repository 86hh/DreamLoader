%include "dreamldr.inc"

bits 32

dreamldr:
        push    esi
        push    ebp
        push    edi
        push    ebx
        
        ;save any other registers here if you want

regstksize      equ     16

        push    60h
        pop     edx
        xor     eax, eax                     ;platform detection trap :)
        push    eax
        dec     eax                          ;REX prefix in 64-bit, but also sets SF in 32-bit
        fs cmovs ebx, dword [30h]            ;now ebx points to PEB in 32-bit
                                             ;yasm doesn't compile this instruction correctly with bits 64
bits 64
        cmovs   edx, esp                     ;known memory to avoid invalid access in 32-bit mode
        gs cmovns rbx, qword [rdx]           ;now rbx points to PEB in 64-bit, in 32-bit this becomes:
                                             ;gs dec eax
                                             ;cmovns ebx, dword [edx]
bits 32
        pop     ecx

;-----------------------------------------------------------------------------
;recover kernel32 image base
;-----------------------------------------------------------------------------

        setz    cl                           ;ZF = 1 in 64-bit
        imul    edi, ecx, 8                  ;qword
        inc     cl
        imul    edx, ecx, 0ch                ;both pebLdr and ldrInLoadOrderModuleList are 0ch
        dec     eax
        mov     ebx, dword [ebx + edx]       ;pebLdr
        add     edx, edi
        dec     eax
        mov     ebx, dword [ebx + edx]       ;ldrInLoadOrderModuleList
        dec     eax
        mov     esi, dword [ebx]
        dec     eax
        lodsd
        push    dword [eax + edi + mlDllBase]
        pop     ebp
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

        dd      0E9258E7Ah                   ;FlushInstructionCache
        dd      0C97C1FFFh                   ;GetProcAddress
        dd      03FC1BD8Dh                   ;LoadLibraryA
        dd      009CE0D4Ah                   ;VirtualAlloc
        db      0

;-----------------------------------------------------------------------------
;platform-independent get architecture by qkumba
;-----------------------------------------------------------------------------

get_arch:
        xor     ecx, ecx
        arpl    cx, cx                       ;movsxd ecx, ecx in x64
        setz    cl
        ret                                  ;ecx -> 0 if x86, 1 if x64

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        dec     cl
        shl     cl, 4
        mov     edx, dword [ebp + lfanew]
        add     edx, ecx
        mov     ebx, dword [ebp + edx + IMAGE_DIRECTORY_ENTRY_EXPORT32]
        xor     edx, edx
        pop     esi

walk_names:
        db      0ffh, 0c2h                   ;inc edx
        mov     ecx, dword [ebp + ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNames]
        dec     eax
        add     ecx, ebp
        mov     edi, dword [ecx + edx * 4]
        dec     eax
        add     edi, ebp
        or      eax, -1

crc32_outer:
        xor     al, byte [edi]     
        push    8
        pop     ecx

crc32_inner:
        shr     eax, 1
        jnc     crc32_loop
        xor     eax, 0edb88320h

crc32_loop:
        loop    crc32_inner
        scasb
        cmp     byte [edi], cl
        jne     crc32_outer
        not     eax
        cmp     dword [esi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, dword [ebp + ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNameOrdinals]
        dec     eax
        add     edi, ebp
        movzx   edi, word [edi + edx * 2]
        mov     ecx, dword [ebp + ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfFunctions]
        dec     eax
        add     ecx, ebp
        mov     ecx, dword [ecx + edi * 4]
        dec     eax
        add     ecx, ebp
        push    ecx
        lodsd
        cmp     byte [esi], 0
        jne     walk_names

;-----------------------------------------------------------------------------
;allocate space for mapstk, and make stack frame
;align stack because at this time we don't know if aligned for sure
;-----------------------------------------------------------------------------

        push    ecx
        push    ecx
        push    ecx
        push    esp
        pop     ebx
        dec     eax
        sub     esp, 40h                     ;only 20h bytes required for shadow stack
        dec     eax
        and     esp, -10h                    ;align on 16-byte boundary

;-----------------------------------------------------------------------------
;allocate memory for mapping
;-----------------------------------------------------------------------------

        call    get_arch
        inc     cl
        imul    edi, ecx, mapstk_size + krncrcstk_size + regstksize + 4
                                             ;+4 to go over return address 
        dec     eax
        mov     esi, dword [ebx + edi]       ;get pointer to PE file
        mov     ebp, dword [esi + lfanew]
        dec     eax
        add     ebp, esi
        push    PAGE_EXECUTE_READWRITE
        inc     ecx
        pop     ecx                          ;r9 = PAGE_EXECUTE_READWRITE
        push    ecx                          ;only works in 32-bit mode, in 64-bit makes 1 slot for shadow stack
        inc     ecx
        mov     eax, MEM_COMMIT | MEM_RESERVE;r8d = MEM_COMMIT | MEM_RESERVE
        push    eax                          ;only works in 32-bit mode, in 64-bit makes 1 slot for shadow stack
        mov     edx, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER32.ohSizeOfImage]
        push    edx
        xor     ecx, ecx                     ;rcx = 0
        push    ecx
        push    mapstk_size + krncrcstk.kVirtualAlloc
        pop     eax
        call    jump_intoapi
        push    eax
        pop     dword [ebx]

;-----------------------------------------------------------------------------
;map MZ header, NT Header, FileHeader, OptionalHeader, all section headers...
;-----------------------------------------------------------------------------

        push    eax
        pop     edi
        mov     ecx, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER32.ohSizeOfHeaders]
        push    esi
        rep     movsb
        pop     esi

;-----------------------------------------------------------------------------
;map sections data
;-----------------------------------------------------------------------------

        mov     cx, word [ebp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhSizeOfOptionalHeader]
        dec     eax
        lea     edx, dword [ebp + ecx + _IMAGE_NT_HEADERS.nthOptionalHeader]
        mov     cx, word [ebp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhNumberOfSections]

map_section:
        push    ecx
        push    esi
        mov     ecx, dword [edx + _IMAGE_SECTION_HEADER.shPointerToRawData]
        dec     eax
        add     esi, ecx 
        mov     edi, dword [edx + _IMAGE_SECTION_HEADER.shVirtualAddress]
        dec     eax
        add     edi, dword [ebx]
        mov     ecx, dword [edx + _IMAGE_SECTION_HEADER.shSizeOfRawData]
        rep     movsb
        pop     esi
        pop     ecx
        dec     eax
        add     edx, _IMAGE_SECTION_HEADER_size
        loop    map_section

;-----------------------------------------------------------------------------
;import DLL
;-----------------------------------------------------------------------------

        call    get_arch
        push    ecx
        inc     cl
        dec     eax
        mov     dword [ebx + ecx * 8], ebp   ;save ebp/rbp for later 
        pop     ecx
        shl     cl, 4
        mov     ebp, dword [ecx + ebp + IMAGE_DIRECTORY_ENTRY_IMPORT32]
        test    ebp, ebp                     ;check if PE has import table
        je      import_skip                  ;if import table not found, skip loading
        dec     eax
        add     ebp, dword [ebx]

import_dll:
        mov     ecx, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idName]
        test    ecx, ecx
        je      import_getbp
        dec     eax
        add     ecx, dword [ebx]
        push    ecx
        push    ecx                          ;must be pushed twice to keep stack aligned for 64-bit
        push    mapstk_size + krncrcstk.kLoadLibraryA
        pop     eax
        call    jump_intoapi
        push    eax
        call    get_arch
        inc     cl
        pop     dword [ebx + ecx * 4]        ;save HMODULE in mapstk.hModule
        pop     eax                          ;pop eax in 32-bit, pop a slot in 64-bit
        dec     cl
        dec     eax
        lea     esp, dword [esp + ecx * 8]   ;discard one more slot in 64-bit
        mov     edi, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idFirstThunk]
        mov     esi, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idOriginalFirstThunk]
        test    esi, esi
        cmove   esi, edi                     ;if OriginalFirstThunk is NULL, esi = edi = FirstThunk
        dec     eax
        add     edi, dword [ebx]
        dec     eax
        add     esi, dword [ebx]
        dec     eax
        add     ebp, _IMAGE_IMPORT_DESCRIPTOR_size

import_thunks:
        dec     eax
        lodsd
        push    eax
        pop     edx
        dec     eax
        test    edx, edx
        je      import_dll
        call    get_arch
        push    32
        pop     eax
        shl     eax, cl
        lea     ecx, dword [eax - 1]
        dec     eax
        btr     edx, ecx
        jc      import_mov
        dec     eax
        add     edx, dword [ebx]
bits 64
        inc     rdx
        inc     rdx
bits 32

import_mov:
        push    edx
        call    get_arch
        inc     cl
        dec     eax
        mov     ecx, dword [ebx + ecx * 4]
        push    ecx
        push    mapstk_size + krncrcstk.kGetProcAddress
        pop     eax
        call    jump_intoapi
        push    eax
        pop     dword [edi]
        call    get_arch
        shl     ecx, 4
        dec     eax
        add     esp, ecx
        dec     eax
        scasd
        jmp     import_thunks

import_getbp:
        call    get_arch
        push    ecx
        inc     cl
        dec     eax
        mov     ebp, dword [ebx + ecx * 8]   ;restore ebp/rbp 

import_skip:

;-----------------------------------------------------------------------------
;apply relocations
;-----------------------------------------------------------------------------

        pop     ecx
        shl     cl, 4
        mov     edi, dword [ebp + ecx + IMAGE_DIRECTORY_ENTRY_RELOCS32]
        test    edi, edi
        je      reloc_skip
        dec     eax
        add     edi, dword [ebx]
        xor     ecx, ecx

reloc_block:
        push    ecx
        push    _IMAGE_BASE_RELOCATION_size
        pop     edx

reloc_addr:
        movzx   eax, word [edi + edx]
        push    eax
        pop     ecx
        and     ah, 0f0h
        cmp     ah, IMAGE_REL_BASED_HIGHLOW << 4
        je      reloc_apply                  ;another type not HIGHLOW
        cmp     ah, IMAGE_REL_BASED_DIR64 << 4
        jne     reloc_abs                    ;another type not DIR64

reloc_apply:
        and     ch, 0fh
        add     ecx, dword [edi + _IMAGE_BASE_RELOCATION.rePageRVA]
        dec     eax
        add     ecx, dword [ebx]             ;new base address
        dec     eax        
        mov     esi, dword [ecx]
        push    ecx
        call    get_arch                     ;ImageBase field is higher in 32-bit PE
        btc     ecx, 0
        dec     eax
        sub     esi, dword [ebp + ecx * 4 + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER64.ohImageBasex]
        pop     ecx
        dec     eax
        add     esi, dword [ebx]
        dec     eax
        mov     dword [ecx], esi
        xor     eax, eax

reloc_abs:
        test    eax, eax                     ;check for IMAGE_REL_BASED_ABSOLUTE
        jne     hldr_exit                    ;not supported relocation type
bits 64
        inc     edx
        inc     edx
bits 32
        cmp     dword [edi + _IMAGE_BASE_RELOCATION.reSizeOfBlock], edx
        jne     reloc_addr
        pop     ecx
        add     ecx, edx
        add     edi, edx
        push    ecx
        push    ecx
        pop     edx
        call    get_arch
        shl     cl, 4
        cmp     dword [ebp + ecx + IMAGE_DIRECTORY_ENTRY_RELOCS32 + 4], edx
        pop     ecx
        jne     reloc_block

reloc_skip:

;-----------------------------------------------------------------------------
;call entrypoint
;-----------------------------------------------------------------------------

        push    ebp
        dec     ebp
        xor     eax, eax
        pop     ebp
        xor     edx, edx
        push    edx
        or      ecx, -1
        push    ecx
        push    mapstk_size + krncrcstk.kFlushInstructionCache
        pop     eax
        call    jump_intoapi
        mov     ecx, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER32.ohAddressOfEntryPoint]
        dec     eax
        add     ecx, dword [ebx]
        call    ecx

hldr_exit:
        call    get_arch
        inc     cl
        imul    edi, ecx, mapstk_size + krncrcstk_size
        lea     esp, qword [ebx + edi]
        pop     ebx
        pop     edi
        pop     ebp
        pop     esi
        pop     ecx
        pop     eax
        jmp     ecx

;-----------------------------------------------------------------------------
;determine platform and dynamically adjust function address size
;-----------------------------------------------------------------------------

jump_intoapi:
        push    ecx                          ;eax = API offset in 32-bit, esi -> platform APIs
        call    get_arch
        shl     eax, cl
        pop     ecx
        jmp     dword [ebx + eax]
dreamldr_end: