/*
 * ⛧ hades_gate.h — Public API for Hades Gate direct syscall technique ⛧
 */

#ifndef HADES_GATE_H
#define HADES_GATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <winternl.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

/*
 * Result from resolving a native API function from ntdll.
 *
 * @address  Pointer to the function in ntdll's export table
 *           (may be hooked by EDR — do not call directly)
 * @ssn      Syscall number extracted from the stub
 *           (use this to build your own clean stub)
 */
typedef struct {
    void*    address;
    uint8_t  ssn;
} HG_RESOLVED;

/* ------------------------------------------------------------------ */
/* Core API                                                           */
/* ------------------------------------------------------------------ */

/*
 * Find the base address of ntdll.dll via PEB walking.
 *
 * Does NOT call GetModuleHandle, LdrGetDllHandle, or any
 * function that could be hooked or monitored.
 *
 * @return  Base address of ntdll.dll, or 0 on failure.
 */
uintptr_t hg_find_ntdll(void);

/*
 * Resolve a named export from ntdll and extract its syscall number.
 *
 * Parses the PE export directory manually, matches the function
 * name via FNV-1a hash, and reads the SSN from the unhooked
 * portion of the syscall stub.
 *
 * @param func_name  Name of the Nt* function to resolve
 *                   (e.g., "NtAllocateVirtualMemory")
 * @return           HG_RESOLVED with {address, ssn}.
 *                   ssn will be 0 if the function is not an Nt*
 *                   syscall or couldn't be resolved.
 */
HG_RESOLVED hg_resolve(const char* func_name);

/*
 * Build a clean syscall stub in executable memory.
 *
 * Synthesizes:
 *   mov r10, rcx
 *   mov eax, SSN
 *   syscall
 *   ret
 *
 * @param ssn  Syscall number to encode into the stub
 * @return     Pointer to executable memory containing the stub,
 *             or NULL on allocation failure.
 */
void* hg_build_stub(uint8_t ssn);

/*
 * One-shot: resolve a named Nt* function and build a clean
 * syscall stub for it.
 *
 * Equivalent to: hg_build_stub(hg_resolve(name).ssn)
 *
 * @param nt_func  Name of the NT function (e.g., "NtAllocateVirtualMemory")
 * @return         Function pointer to a clean syscall stub,
 *                 or NULL if resolution or allocation failed.
 */
void* hg_syscall(const char* nt_func);

/* ------------------------------------------------------------------ */
/* Helper: NTSTATUS typedef for your convenience                      */
/* ------------------------------------------------------------------ */
#ifndef NTSTATUS_OK
#define NTSTATUS_OK ((NTSTATUS)0L)
#endif

#ifdef __cplusplus
}
#endif

#endif /* HADES_GATE_H */
