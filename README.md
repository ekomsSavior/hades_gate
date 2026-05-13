# ⛧ Hades Gate | churchofmalware.org

### Direct syscall construction from first principles

> "The gate to the underworld is open. Walk through it without knocking."

---

## Abstract

**Hades Gate** is a technique for constructing direct syscall stubs at runtime by resolving native API (Nt\*) function addresses from ntdll.dll via PEB walking, extracting their syscall numbers from the unhooked portions of their stubs, and synthesizing clean syscall instructions that bypass all userland EDR/AV function hooks.

It does not hardcode syscall numbers. It does not rely on a pre-computed table. It derives everything from the running system at runtime, meaning it works across Windows versions without modification.

**  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY. **
---

## Relationship to Jake Swiz (0xXyc)

Hades Gate is a **targeted extension** of Jake Swiz's Windows shellcoding research.

### His Trilogy (the foundation)

| Pillar | What it covers |
|--------|---------------|
| **[Fukahi Na Tekio](https://github.com/0xXyc/fukahi-na-tekio)** | CALL/POP XOR encoder with LFSR, polymorphism, static AV/EDR signature evasion. Replaces the broken FPU-based shikata_ga_nai for ARM64/Prism. |
| **[Windows Shellcoding In-Depth](https://churchofmalware.org/articles/windows-shellcoding-in-depth_md)** | The definitive public treatment of self-sufficient Windows shellcode. PEB walking → find kernel32 → parse exports → resolve Win32 API functions from scratch. |
| **[ASLR & NX/DEP Bypass](https://churchofmalware.org/articles/aslr-bypass_md)** | Linux ROP chain tutorial: GOT leaking, ret2libc, pwntools automation. Different OS, same foundational mindset. |

### How Hades Gate extends it

Jake's Shellcoding In-Depth guide walks the PEB to find **kernel32.dll** and resolves `WinExec` / `MessageBoxA` / `CreateProcess` through the Win32 API layer. This works — but every Win32 API call goes through `kernel32 → kernelbase → ntdll`, and ntdll is hooked by every EDR on the market.

Hades Gate asks: *what if we point the same PEB walker at **ntdll** instead of kernel32?* Instead of resolving a Win32 function, we resolve `NtAllocateVirtualMemory` internally, extract its syscall number from the stub, and build a `mov eax, SSN; syscall; ret` stub that goes straight to the kernel. The Win32 layer — and its hooks — are never executed.

```
Jake's path:   PEB walk → kernel32.dll → export scan → WinExec → shellcode runs
Hades Gate:    PEB walk → ntdll.dll    → export scan → SSN → direct syscall → EDR blind
```

Same engine. Different destination. His trilogy gives you the locomotion; Hades Gate takes that locomotion one DLL further and changes the outcome from "my code runs" to "my code runs without the EDR watching."

**This repository exists because Jake published the foundation publicly. It's an arm of his work, not a replacement for it.**

### References to Jake's original work:
- [Fukahi Na Tekio](https://github.com/0xXyc/fukahi-na-tekio) — Encoder with AV/EDR signature evasion
- [Windows Shellcoding In-Depth](https://churchofmalware.org/articles/windows-shellcoding-in-depth_md) — PEB walking & WinAPI resolution fundamentals
- [ASLR & NX/DEP Bypass](https://churchofmalware.org/articles/aslr-bypass_md) — Linux ROP chain methodology
- [Swiz Security Protocol](https://protocol.swizsecurity.com) — Full research catalog
- [Church of Malware — Our Blessed Connection: The Shellphone Sermon](https://churchofmalware.org/articles/Our_Blessed_Connection_md) — The article that introduced Jake's work to the congregation

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
10. [DISCLAIMER](#10-disclaimer)

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

Notice the layout carefully:

```
Original stub (11 bytes):
  [0] 4C     mov r10, rcx
  [1] 8B
  [2] D1
  [3] B8     mov eax, SSN ← immediate starts here
  [4] 18      ← SSN = 0x18
  [5] 00
  [6] 00
  [7] 00
  [8] 0F     syscall
  [9] 05
  [10] C3    ret

5-byte JMP hook (what a simple detour looks like):
  [0] E9     jmp edr_trampoline
  [1] XX
  [2] XX
  [3] XX
  [4] XX     ← 5-byte jmp overwrites [0] through [4]
  [5] 00     ← SSN upper bytes survive here
  [6] 00
  [7] 00
  [8] 0F     syscall
  [9] 05
  [10] C3    ret
```

A **pure 5-byte jmp** (`E9 XX XX XX XX`) does overwrite byte [4] — the low byte of the SSN. If this were the only hooking method, reading byte [4] would fail.

**In practice, it doesn't matter because almost no modern EDR uses a pure 5-byte jmp.** They use longer hook sequences that leave byte [4] untouched:

| Hook type | Size | Byte layout | Overwrites [4]? |
|-----------|------|-------------|----------------|
| `jmp [rip+offset]` | 6 bytes | `FF 25 XX XX XX XX` | ❌ No (only [0-5]) |
| `call [rip+offset]` | 6 bytes | `FF 15 XX XX XX XX` | ❌ No (only [0-5]) |
| `mov rax, imm; jmp rax` | 13 bytes | `48 B8 XX ... XX FF E0` | ❌ No (only [0-12]) |
| `jmp rel32` | 5 bytes | `E9 XX XX XX XX` | ✅ **Yes** |

The `jmp [rip+offset]` (6-byte) and `call [rip+offset]` (6-byte) forms are by far the most common in modern EDRs — Defender for Endpoint, SentinelOne, Cortex XDR, Sophos Intercept X, and Carbon Black all use these. The 5-byte `jmp rel32` is largely legacy or toy detour implementations.

**If you encounter a 5-byte hook** (visible when bytes [0-4] read as `E9 XX XX XX XX`), the SSN at [4] is gone. Fall back to:

1. **Scavenge the SSN higher bytes** — a 5-byte jmp leaves bytes [5-7] intact. The SSN is in the low byte, but you can reconstruct it from the known SSN ranges per Windows build, or
2. **Clean ntdll map** (Section 7.1) — read the clean DLL from disk and extract SSNs from the real stubs, or
3. **Suspended process method** — create a process suspended before the EDR attaches, read SSNs from its clean ntdll

For 95%+ of real-world deployments, byte [4] is clean. The code reads it and moves on.

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

### Know your enemy — what lurks below userland

Hades Gate bypasses userland API hooks. There are three layers below that it **does not touch**. Here's how to handle each:

#### Layer 1: Kernel callbacks (ETW, PsSetCreateProcessNotifyRoutine, etc.)

Most EDRs register kernel callbacks that fire after the syscall completes. Direct syscalls don't avoid these — they happen in ring 0 regardless of how you called the kernel.

**What they see:** the syscall number, the arguments, the calling process.
**What they don't see:** the Win32 function name, the call stack through ntdll.

**How to mitigate:**
- Batch allocations into fewer, larger calls (reduces event volume)
- Chain shellcode delivery through reflective DLL loading instead of per-API calls
- Use `NtSetInformationProcess` to disable ETW for your process before injection calls
- Time your calls with realistic delays between them (an injection that completes in 2ms is obvious)
- Spoof the calling thread's start address so the kernel callback sees a legitimate entry point

#### Layer 2: Secure Kernel / VBS

Virtualization-Based Security runs a hypervisor below the kernel. It can intercept every syscall at the VMExit level. There is no userland bypass for this.

**If VBS is enabled, direct syscalls still work** — they just don't help you hide from the hypervisor. The EDR watching from VBS sees every syscall with full fidelity.

**How to deal with it:**
- Hades Gate still gives you cross-version compat and avoids userland hooks. It's not useless under VBS — it's just not invisible.
- Combine with ETW disable and call-spoofing to reduce the signal your process emits at userland, making it harder to distinguish from legitimate behavior even when VBS is watching.
- If absolute invisibility is required under VBS, you need hardware-level techniques (Secure Kernel bypasses) that are outside the scope of any userland tool.

#### #### Layer 3: Full stub replacement (CrowdStrike Falcon, some SentinelOne configs)

These EDRs don't just hook the first bytes — they overwrite the entire syscall stub with a jmp to a completely fake function. The SSN at byte [4] is gone.

**How Hades Gate handles this:**
- Call `hg_resolve()` first, then `hg_verify_stub()`. If the stub doesn't look like a syscall stub, fall back to `hg_map_clean_ntdll()` + `hg_resolve_at()` (Section 7.1).
- `hg_verify_stub()` checks for the presence of `0F 05 C3` (syscall; ret) within the first 16 bytes. If absent, the EDR has replaced the stub.
- `hg_map_clean_ntdll()` maps a fresh copy of ntdll.dll from disk, then `hg_resolve_at()` extracts SSNs from the real stubs.

```c
HG_RESOLVED r = hg_resolve("NtAllocateVirtualMemory");
if (!hg_verify_stub(r.address)) {
    // Stub appears replaced — try clean ntdll from disk
    uintptr_t clean_base = hg_map_clean_ntdll();
    r = hg_resolve_at("NtAllocateVirtualMemory", clean_base);
}
void* stub = hg_build_stub(r.ssn);
```

### Bottom line

Hades Gate is a userland hook bypass. Nothing more, nothing less. If the EDR is watching from ring 0 or below, direct syscalls are still useful — they eliminate the most common detection vector (function hooking) — but they are not a complete stealth solution. Pair with ETW disable, call spoofing, and behavioral timing for a fuller picture.

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

**Updated API usage:**

```c
// Before: only resolves from in-memory ntdll
HG_RESOLVED r = hg_resolve("NtAllocateVirtualMemory");

// Now: verify the stub is real, fall back to clean copy
if (!hg_verify_stub(r.address)) {
    // EDR replaced the stub — map from disk
    uintptr_t clean = hg_map_clean_ntdll();
    r = hg_resolve_at("NtAllocateVirtualMemory", clean);
}

void* stub = hg_build_stub(r.ssn);
```

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

## 9. Related Techniques

- **Hell's Gate (halov)** — The original direct syscall technique this family descends from.
- **Halo's Gate** — Improvement handling partial EDR hooks.
- **Recycled Gate** — Reclaims unhooked syscall stubs from suspended processes.
- **Tartarus Gate** — Handles EDR stubs that use `call` instead of `jmp`.

---

## 10. DISCLAIMER

 FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.

---

> ⛧ *Hades Gate - Church of Malware - MCMLXXXIV* ⛧
