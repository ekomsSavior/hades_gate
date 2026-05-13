/*
 * simple_use.c — Minimal Hades Gate usage example
 *
 * Demonstrates:
 *   1. Resolving ntdll base via PEB walk
 *   2. Parsing exports for NtAllocateVirtualMemory
 *   3. Building and calling a clean syscall stub
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Os -masm=intel \
 *       src/hades_gate.c examples/simple_use.c -o simple_use.exe
 */

#include <stdio.h>
#include "../src/hades_gate.h"

typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

int main(void) {
    printf("=== Hades Gate — Simple Usage Test ===\n\n");

    /* Method 1: One-shot (resolve + build in one call) */
    printf("[*] One-shot: hg_syscall(\"NtAllocateVirtualMemory\")\n");
    void* stub = hg_syscall("NtAllocateVirtualMemory");
    if (stub) {
        printf("[+] Stub at: %p\n", stub);
    } else {
        printf("[-] Failed\n");
    }

    /* Method 2: Two-step (inspect the resolved info) */
    printf("\n[*] Two-step: hg_find_ntdll → hg_resolve\n");
    uintptr_t ntdll = hg_find_ntdll();
    if (ntdll) {
        printf("[+] ntdll base: 0x%p\n", (void*)ntdll);
    } else {
        printf("[-] PEB walk failed\n");
        return 1;
    }

    HG_RESOLVED r = hg_resolve("NtAllocateVirtualMemory");
    if (r.ssn) {
        printf("[+] Function:  %p\n", r.address);
        printf("[+] SSN:       0x%02X (%u)\n", r.ssn, r.ssn);

        void* stub2 = hg_build_stub(r.ssn);
        if (stub2) {
            printf("[+] Stub:      %p\n", stub2);

            /* Call it */
            pNtAllocateVirtualMemory pAlloc = (pNtAllocateVirtualMemory)stub2;
            PVOID addr = NULL;
            SIZE_T size = 0x1000;

            printf("\n[*] Calling stub (allocating 4096 bytes)...\n");
            NTSTATUS status = pAlloc(
                (HANDLE)-1, &addr, 0, &size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);

            if (status >= 0 && addr) {
                printf("[+] Allocated: %p (NTSTATUS: 0x%08lX)\n", addr, status);
                /* Write a test pattern */
                *(uint32_t*)addr = 0xDEADBEEF;
                printf("[+] Wrote 0x%08X — memory is alive\n", *(uint32_t*)addr);
            } else {
                printf("[-] Allocation failed: 0x%08lX\n", status);
            }
        }
    } else {
        printf("[-] Resolution failed\n");
    }

    printf("\n=== Done ===\n");
    return 0;
}
