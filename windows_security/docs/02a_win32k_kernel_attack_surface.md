# Win32k Kernel Attack Surface — GDI, Window Manager, Clipboard & CVE Analysis

> A deep-technical reference on the Win32k subsystem attack surface: GDI objects, User mode driver framework, window manager, clipboard, DDE, menu/class/hook vulnerabilities, and detailed CVE analysis. Written for exploit developers, kernel security researchers, and OSEE candidates.

---

## Table of Contents

1. [Win32k Overview](#1-win32k-overview)
2. [Win32k Architecture](#2-win32k-architecture)
3. [GDI Objects & Attack Surface](#3-gdi-objects--attack-surface)
4. [Window Manager (USER) Attack Surface](#4-window-manager-user-attack-surface)
5. [Callback Mechanisms](#5-callback-mechanisms)
6. [Win32k Syscall Table](#6-win32k-syscall-table)
7. [Clipboard & DDE Attack Surface](#7-clipboard--dde-attack-surface)
8. [Menu, Class & Hook Vulnerabilities](#8-menu-class--hook-vulnerabilities)
9. [CVE Analysis: CVE-2019-0808](#9-cve-analysis-cve-2019-0808)
10. [CVE Analysis: CVE-2020-0986](#10-cve-analysis-cve-2020-0986)
11. [CVE Analysis: CVE-2021-1732](#11-cve-analysis-cve-2021-1732)
12. [CVE Analysis: CVE-2022-21882](#12-cve-analysis-cve-2022-21882)
13. [Win32k Exploitation Patterns](#13-win32k-exploitation-patterns)
14. [Mitigations & Hardening](#14-mitigations--hardening)

---

## 1. Win32k Overview

`win32k.sys` is the Windows kernel-mode driver that implements the Win32 GUI subsystem. It is arguably the largest and most exposed attack surface in the Windows kernel, sitting at the boundary between user-mode GUI applications and kernel-mode execution. At over 2,000 system calls (compared to ~480 NT system calls in `ntoskrnl.exe`), Win32k dwarfs the core kernel in terms of syscall surface area.

Win32k was introduced in Windows NT 4.0 (1996) to move the Graphics Device Interface (GDI) from user mode to kernel mode for performance reasons. This architectural decision created an enormous kernel attack surface that persists 28 years later.

```
Win32k Position in Windows Architecture:
┌─────────────────────────────────────────────────────────┐
│ User Mode (Ring 3)                                      │
│  ┌──────────┐ ┌──────────┐ ┌───────────────────┐     │
│  │ user32.dll│ │ gdi32.dll │ │ win32u.dll        │     │
│  │ (Win32    │ │ (GDI      │ │ (syscall stubs)  │     │
│  │  USER)    │ │  wrapper) │ │                   │     │
│  └────┬─────┘ └─────┬────┘ └──────┬────────────┘     │
│       │              │             │ syscall             │
├───────┼──────────────┼─────────────┼─────────────────────┤
│ Kernel Mode (Ring 0)                                     │
│  ┌──────▼──────────────▼─────────────▼────────────────┐ │
│  │ win32k.sys (2,000+ syscalls)                      │ │
│  │ ┌──────────────┐ ┌──────────────┐ ┌────────────┐ │ │
│  │ │ GDI Engine   │ │ USER Engine  │ │ DirectDraw │ │ │
│  │ │ (Drawing,    │ │ (Windows,    │ │ /DXGKRNL   │ │ │
│  │ │  Fonts,      │ │  Messages,   │ │ (GPU       │ │ │
│  │ │  Surfaces)   │ │  Hooks)      │ │  Scheduler)│ │ │
│  │ └──────────────┘ └──────────────┘ └────────────┘ │ │
│  └──────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────┐ │
│  │ ntoskrnl.exe (Executive, Memory, I/O Manager)  │ │
│  └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Key security properties of Win32k:**

- **Runs in kernel mode**: All Win32k code executes at Ring 0, meaning any vulnerability enables full system compromise.
- **Enormous attack surface**: Over 2,000 system calls, each with multiple parameters, many processing complex structures from user mode.
- **Callback-heavy architecture**: Win32k frequently calls back into user mode, creating re-entrancy and TOCTOU vulnerabilities.
- **Complex state management**: Window stations, desktops, windows, menus, hooks, accelerators, and GDI objects form a deeply interconnected object graph.
- **Legacy compatibility**: Win32k must maintain backward compatibility with 30+ years of applications, making aggressive refactoring difficult.

---

## 2. Win32k Architecture

### 2.1 Major Components

Win32k is divided into three major subsystems:

#### GDI (Graphics Device Interface)

GDI handles all 2D graphics rendering, font management, and surface manipulation. Key object types:

| Object Type | Create API | Handle Type | Pool Allocation |
|-------------|-----------|-------------|----------------|
| Bitmap | `CreateBitmap` | `HBITMAP` | Paged pool |
| Brush | `CreateSolidBrush` | `HBRUSH` | Paged pool |
| Font | `CreateFontIndirect` | `HFONT` | Paged pool |
| Pen | `CreatePen` | `HPEN` | Paged pool |
| Region | `CreateRectRgn` | `HRGN` | Paged pool |
| Palette | `CreatePalette` | `HPALETTE` | Paged pool |
| DC (Device Context) | `CreateCompatibleDC` | `HDC` | Paged pool |
| Metafile | `CreateMetaFile` | `HMETAFILE` | Paged pool |
| Enhanced Metafile | `CreateEnhMetaFile` | `HENHMETAFILE` | Paged pool |
| Path | `BeginPath` | (internal) | Paged pool |
| Surface | `EngCreateSurface` | `HSURF` | Paged pool |

#### USER (Window Manager)

USER handles window management, message routing, input processing, and the desktop/window station model. Key object types:

| Object Type | Create API | Handle Type | Pool Allocation |
|-------------|-----------|-------------|----------------|
| Window | `CreateWindowEx` | `HWND` | Paged pool (win32k!VerifyWnd) |
| Menu | `CreateMenu` | `HMENU` | Paged pool |
| Hook | `SetWindowsHookEx` | `HHOOK` | Paged pool |
| Timer | `SetTimer` | (UINT) | Paged pool |
| Accelerator | `CreateAcceleratorTable` | `HACCEL` | Paged pool |
| Cursor | `CreateCursor` | `HCURSOR` | Paged pool |
| Icon | `CreateIconIndirect` | `HICON` | Paged pool |
| Window Station | `CreateWindowStation` | `HWINSTA` | Non-paged pool |
| Desktop | `CreateDesktop` | `HDESK` | Paged pool |
| Message Queue | (per-thread) | (internal) | Paged pool |
| DDE Conversation | `DdeConnect` | `HCONV` | Paged pool |

#### DirectDraw/DXGKRNL

The DirectX Graphics Kernel (`dxgkrnl.sys`) handles GPU scheduling, video memory management, and 3D rendering. While technically separate from `win32k.sys`, it shares the same attack surface category (kernel-mode graphics). See the `→ 02b_nt_kernel_vulnerabilities` track for DXGKRNL CVEs.

### 2.2 Handle Table and Object Management

Win32k maintains its own handle table separate from the NT Object Manager. The Win32k handle table (`ghandleTable`) maps `Hxxxx` handles to internal kernel objects:

```c
// Simplified Win32k handle table structure
// Each entry is 8 bytes (or 16 bytes on 64-bit):
typedef struct _HANDLEENTRY {
    PVOID   phead;      // Pointer to object header (HEAD structure)
    ULONG   bAuditClose : 1;    // Audit on close
    ULONG   bDestroyOnClose : 1; // Destroy when handle closed
    ULONG   fHandleOwner : 1;    // Handle ownership flag
    ULONG   fInDestroy : 1;      // Object being destroyed
    ULONG   bLastHandle : 1;    // Last handle for this process
    ULONG   bNeedCleanup : 1;   // Needs process cleanup
    ULONG   bDestroyOnUnlock : 1; // Destroy on last unlock
    ULONG   fAllocated : 1;     // Handle is allocated
    // ... more flags
    PTHREADINFO pti;      // Owning thread (or POWNER_THREADINFO)
    BYTE    bType;         // Object type index (TYPE_WINDOW, TYPE_MENU, etc.)
    BYTE    bUnique;       // Handle uniqueness counter (increments on reuse)
} HANDLEENTRY, *PHANDLEENTRY;

// Handle format (32-bit):
// Bits 31-16: Handle index (into handle table)
// Bits 15-0:  Uniqueness value (bUnique counter)
// 
// This means handle values wrap and can be predicted if the uniqueness counter
// is known, enabling handle manipulation attacks.
```

The `phead` field points to a `HEAD` structure at the beginning of every Win32k object:

```c
typedef struct _HEAD {
    HANDLE  h;              // Handle value (self-reference)
    ULONG   cLockObj;       // Reference count (lock count)
} HEAD, *PHEAD;

typedef struct _THROBJHEAD {    // Used for thread-owned objects
    HEAD    head;
    PTHREADINFO pti;       // Owning thread info
} THROBJHEAD;

typedef struct _THREADHEAD {   // Used for per-thread objects
    THROBJHEAD  head;
    DWORD       dwThreadId;   // Thread ID
} THREADHEAD;
```

The `cLockObj` field is a reference count that tracks how many times the object has been locked via `HmgLockObject`. When it drops to zero, the object can be freed. This is a frequent source of use-after-free vulnerabilities when reference count mismatches occur between the lock path and unlock path.

### 2.3 Window Stations and Desktops

Win32k uses a three-level hierarchy for GUI object isolation:

```
Session (Session 0, Session 1, ...)
  │
  ├── Window Station (WinSta0, ...)
  │     │
  │     ├── Desktop (Default, Winlogon, ScreenSaver, ...)
  │     │     │
  │     │     ├── Window (top-level, child, owned, ...)
  │     │     ├── Menu
  │     │     ├── Hook (WH_CALLWNDPROC, WH_GETMESSAGE, etc.)
  │     │     └── Message Queue
  │     │
  │     └── Desktop (alternate)
  │
  └── Window Station (alternate, for services)
```

- **Session**: A Terminal Services session. Session 0 is for services (non-interactive), Session 1+ for interactive users.
- **Window Station**: Contains a clipboard, atom table, and one or more desktops. `WinSta0` is the interactive window station.
- **Desktop**: Contains windows, menus, and hooks. Each desktop has its own message queue and hook chain.

**Security implication**: Services running in Session 0 share `WinSta0` with the interactive user (in older Windows versions). This was a major attack vector for shatter attacks (window message exploitation). Modern Windows isolates services in a separate window station.

---

## 3. GDI Objects & Attack Surface

### 3.1 GDI Object Lifecycle

GDI objects follow a create/use/destroy lifecycle. The key operations are:

```c
// Create a bitmap (simplified)
HBITMAP hBitmap = CreateBitmap(width, height, planes, bpp, bits);
// → Win32k allocates SURFOBJ + pixel buffer in paged pool
// → Returns handle to user mode

// Select into DC
HGDIOBJ hOld = SelectObject(hdc, hBitmap);
// → Increments reference count on new bitmap
// → Decrements reference count on old bitmap

// Delete (free)
BOOL result = DeleteObject(hBitmap);
// → Decrements reference count
// → If count == 0: frees SURFOBJ + pixel buffer
```

### 3.2 SURFOBJ Structure

The `SURFOBJ` (Surface Object) is the core GDI data structure for bitmaps:

```c
// Simplified SURFOBJ (public definition from winddi.h)
typedef struct _SURFOBJ {
    DHSURF   dhsurf;        // Driver-private surface handle
    HSURF    hsurf;         // GDI surface handle
    DHPDEV   dhpdev;        // Driver-private PDEV handle
    HDEV     hdev;          // GDI PDEV handle
    SIZEL    sizlBitmap;    // Width and height
    ULONG    cxBitmap;      // Width in pixels
    ULONG    cyBitmap;      // Height in pixels (redundant with sizlBitmap)
    PVOID    pvBits;         // Pointer to pixel data (KERNEL-MODE ADDRESS!)
    ULONG    lDelta;        // Row stride (bytes per scanline)
    ULONG    iUniq;         // Unique surface identifier
    ULONG    iBitmapFormat; // Pixel format (BMF_8PPP, BMF_32BPP, etc.)
    USHORT   fjBitmap;      // Flags (BMF_HBMMASK, etc.)
    USHORT   fjUnsure;      // More flags
} SURFOBJ;
```

The `pvBits` field is critical for exploitation: it contains the kernel-mode virtual address of the bitmap's pixel buffer. If an attacker can leak this address (through an information leak vulnerability), they can use it to calculate the address of the `SURFOBJ` structure itself and modify bitmap metadata to achieve arbitrary kernel read/write.

### 3.3 GDI Pool Attack Patterns

GDI objects are allocated from the paged pool, making them attractive targets for pool corruption exploits (see `→ 03b_pool_corruption_exploitation`). The classic pattern is:

```
1. SPRAY: Allocate many GDI objects of the same size to fill pool chunks
2. HOLE: Free one or more objects to create holes in the allocation pattern
3. TRIGGER: Trigger a vulnerability (overflow, UAF, etc.) that corrupts adjacent pool chunks
4. CONTROL: Use the corrupted GDI object to read/write kernel memory
5. ESCALATE: Modify process token or create a privileged process
```

**Bitmap arbitray read/write primitive:**

```c
// Classic GDI bitmap read/write primitive (pre-Windows 10 RS1)
// Step 1: Leak SURFOBJ.pvBits address through info leak vulnerability
// Step 2: Modify pvBits via overflow/UAF to point to target address
// Step 3: Use SetBitmapBits/GetBitmapBits to read/write arbitrary kernel memory

// Read kernel memory:
PVOID target_addr = 0xFFFF800012345678; // Target kernel address
// Overwrite pvBits of "manager" bitmap to point to target_addr
// This is done by writing to the SURFOBJ.pvBits field
SetBitmapBits(hManagerBitmap, sizeof(PVOID), &target_addr);  // Overwrite pvBits
BYTE buffer[8];
GetBitmapBits(hWorkerBitmap, 8, buffer);  // Read 8 bytes from target_addr

// Write kernel memory:
BYTE data[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
// Overwrite pvBits of "manager" bitmap to point to target_addr first
SetBitmapBits(hManagerBitmap, sizeof(PVOID), &target_addr);
SetBitmapBits(hWorkerBitmap, 8, data);  // Write 8 bytes to target_addr
```

> **Note**: This classic technique was mitigated in Windows 10 RS1 (1607) by introducing `Win32kPool` separation — GDI objects are now allocated from a separate pool (`Win32k!GdiPool`) that is not adjacent to other kernel objects.

---

## 4. Window Manager (USER) Attack Surface

### 4.1 Window Messages

Window messages are the fundamental communication mechanism in the USER subsystem. Every GUI operation involves sending or posting messages to windows. The message processing pipeline creates multiple attack surfaces:

```
Message Flow:
┌───────────────┐     ┌──────────────┐     ┌──────────────────┐
│ Sending Thread │────►│ Message Queue │────►│ Receiving Thread  │
│ (SendMessage)  │     │ (in kernel)  │     │ (WndProc)        │
└───────────────┘     └──────────────┘     └──────────────────┘
      │                    │                       │
      │                    │                       │
      ▼                    ▼                       ▼
  Synchronous        Queueing              Dispatch to
  send (blocked)     (async)               kernel callback
  until WndProc      (PostMessage)         (user-mode WndProc)
  returns
```

Key message types and their security implications:

| Message | Value | Source | Security Impact |
|---------|-------|--------|-----------------|
| `WM_TIMER` | 0x0113 | Kernel | Can specify arbitrary WndProc (callback hijacking) |
| `WM_SETFONT` | 0x0030 | User | Font object reference, potential UAF |
| `WM_GETTEXT` | 0x000D | User | Buffer overflow if length not checked |
| `WM_COPYDATA` | 0x004A | User | Cross-process data transfer, potential pool overflow |
| `WM_DESTROY` | 0x0002 | Kernel | Object destruction, potential UAF |
| `WM_NCDESTROY` | 0x0082 | Kernel | Final window destruction, re-entrancy |
| `EM_SETSEL` | 0x0051 | User | Edit control selection, potential buffer overflow |

### 4.2 Window Procedure Callbacks

Window procedures are the most critical attack surface in Win32k. They are user-mode function pointers that the kernel calls back to:

```c
// Window procedure called from kernel:
LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

// When kernel calls this, execution transitions:
// 1. Kernel identifies target window's WndProc
// 2. Kernel calls KeUserModeCallback (or KiUserCallbackDispatcher)
// 3. User-mode callback dispatcher invokes WndProc
// 4. WndProc returns result
// 5. Kernel continues processing
```

The callback mechanism (`KeUserModeCallback` → `KiUserCallbackDispatcher`) is a security boundary crossing that creates re-entrancy problems. During the callback, user-mode code can:

1. **Destroy the window being processed**: The kernel holds a reference to a `WINDOW` object, but user-mode code can destroy the window, causing a use-after-free when the kernel resumes.
2. **Modify hooks**: Add or remove hooks that change the message processing chain.
3. **Change window properties**: Modify the WndProc pointer, window data, or parent/child relationships.

This re-entrancy is the root cause of many Win32k CVEs (CVE-2021-1732, CVE-2022-21882, etc.).

### 4.3 Hook Procedures

Windows hooks (`SetWindowsHookEx`) allow code injection into the message processing chain of other threads:

```c
// Install a hook (user-mode):
HHOOK SetWindowsHookEx(
    int idHook,        // Hook type (WH_CALLWNDPROC, WH_GETMESSAGE, etc.)
    HOOKPROC lpfn,     // Hook procedure
    HINSTANCE hMod,    // DLL containing hook procedure
    DWORD dwThreadId   // Target thread (0 = all threads)
);

// Hook types and their kernel processing:
WH_CALLWNDPROC    → kernel calls hook before SendMessage delivery
WH_CALLWNDPROCRET → kernel calls hook after SendMessage delivery
WH_GETMESSAGE     → kernel calls hook during GetMessage/PeekMessage
WH_KEYBOARD_LL    → kernel calls hook before key input processing (low-level)
WH_MOUSE_LL       → kernel calls hook before mouse input processing (low-level)
WH_CBT            → kernel calls hook on window activation, creation, etc.
WH_SHELL          → kernel calls hook on shell events
WH_MSGFILTER      → kernel calls hook during dialog/message box processing
WH_SYSMSGFILTER   → kernel calls hook during system message processing
WH_FOREGROUNDIDLE → kernel calls hook when foreground thread is idle
WH_DEBUG          → kernel calls hook before other hooks (debugging)
```

**Security implications of hooks:**

- **Cross-process injection**: A hook installed with `dwThreadId=0` (global hook) will load the specified DLL into every GUI thread's address space. This is a common persistence and injection mechanism.
- **Hook chain corruption**: If a hook procedure modifies the hook chain (adds or removes hooks during processing), the kernel's bookkeeping can become inconsistent, leading to use-after-free or type confusion.
- **Shatter attacks**: Sending specific window messages (`WM_TIMER` with a custom timer procedure) to privileged processes that have exposed window handles can achieve code execution at the target process's privilege level.

---

## 5. Callback Mechanisms

### 5.1 Kernel-to-User Callbacks

Win32k uses `KeUserModeCallback` to invoke user-mode code from kernel mode. This is the core mechanism for window message processing, property enumeration, and hook dispatch. The callback flow:

```
1. Win32k processes a window message (e.g., WM_SETFONT)
2. Win32k determines the target window's WndProc
3. Win32k calls KeUserModeCallback(FunctionTableIndex, ArgumentBuffer, ArgumentLength, ...)
4. Kernel transitions to user mode via KiUserCallbackDispatcher
5. User-mode callback dispatcher invokes the registered WndProc
6. WndProc processes the message (user-mode code executes)
7. WndProc returns result via NtCallbackReturn
8. Kernel resumes execution in Win32k

--- DURING STEP 6, USER-MODE CODE CAN ---
--- DESTROY WINDOWS, MODIFY HOOKS, FREE --
--- GDI OBJECTS, CHANGE WINDOW PROPERTIES --
-------------------------------------------
```

This callback mechanism creates a fundamental problem: **between the kernel's security check and the kernel's use of a pointer, user-mode code can invalidate the pointer**. This is the classic TOCTOU (Time-of-Check-to-Time-of-Use) pattern in Win32k:

```c
// Vulnerable pattern in Win32k callback handling:
// STEP 1: Kernel validates window pointer
pwnd = ValidateHwnd(hwnd);  // Check: window is valid
if (pwnd == NULL) return ERROR;

// STEP 2: Kernel initiates callback
KeUserModeCallback(...);  // User-mode code can destroy window here!

// STEP 3: Kernel uses window pointer (USE-AFTER-FREE!)
pwnd->state |= WF_DESTROYED;  // pwnd may be freed!
```

### 5.2 Win32k Callback Re-entrancy Patterns

Re-entrancy bugs in Win32k callbacks follow several patterns:

**Pattern 1: Object Destruction During Callback**

```c
// Pseudocode for CVE-2021-1732 class of bugs
NTSTATUS xxxCreateWindowEx(...) {
    pwnd = AllocateWindow(...);
    pwnd->style = style;
    
    // Callback to user mode (WndProc for WM_CREATE)
    result = xxxSendMessage(pwnd, WM_CREATE, ...);
    
    // After callback, pwnd may be freed if WM_CREATE handler
    // called DestroyWindow or similar
    // Accessing pwnd here is USE-AFTER-FREE
    pwnd->state |= WF_CREATED;  // BUG: pwnd may be invalid
}
```

**Pattern 2: Double Fetch**

```c
// Pseudocode for double-fetch in callback
NTSTATUS xxxSetFont(...) {
    // First fetch from user mode
    hFont = (HFONT)lParam;
    pfont = ValidateFont(hFont);  // Validate
    
    // Callback
    xxxSendMessage(...);  // User can change hFont in same memory
    
    // Second fetch from same user-mode address
    // Attacker may have changed the value
    hFont2 = *(HFONT*)userAddress;  // Different value!
    pfont2 = ValidateFont(hFont2);  // Different font object
}
```

**Pattern 3: Type Confusion via State Change**

```c
// A window's type can change during a callback
// The kernel may check the type before the callback,
// but user-mode code can change it during the callback
NTSTATUS xxxSetWindowLong(...) {
    if (pwnd->style & WS_CHILD) {
        // Handle child window case
        // ...
    }
    // Callback to user mode
    xxxSendMessage(pwnd, WM_STYLECHANGED, ...);
    // After callback, pwnd->style may have changed
    // Now pwnd is no longer a child window, but code
    // assumes it still is → type confusion
}
```

---

## 6. Win32k Syscall Table

### 6.1 Win32k System Call Dispatching

Win32k system calls use the shadow SSDT (System Service Dispatch Table). On x64 Windows, the dispatching goes through `win32k.sys` rather than `ntoskrnl.exe`:

```c
// Win32k syscall dispatching:
// User mode: NtUserCreateWindowEx → win32u.dll → syscall instruction
// Kernel mode: KiSystemServiceShadow → Win32k service table
//
// The shadow table is separate from the main SSDT:
KeServiceDescriptorTable[1] = {
    .Base = KiServiceTableShadow,  // Win32k service table
    .Count = NULL,                   // Not used (Win32k uses variable args)
    .Limit = Win32kServiceCount,   // Number of services
    .Number = Win32kArgumentTable  // Argument size table
};
```

### 6.2 Notable Win32k System Calls

Below is a selection of the most security-relevant Win32k syscalls, grouped by category:

**Window Management:**
```c
NtUserCreateWindowEx       // Create window
NtUserDestroyWindow        // Destroy window
NtUserSetWindowLong        // Modify window attributes (HIGH RISK)
NtUserSetWindowLongPtr     // Modify window pointer attributes
NtUserFindWindowEx         // Find windows (information disclosure)
NtUserGetClassName         // Get class name (information leak)
NtUserSetParent             // Change window parent (reparenting attack)
NtUserSetWindowWord         // Modify window word-size data
NtUserSetWindowPos         // Change window position/Z-order
NtUserMessageCall           // Send message to window (callback dispatch)
NtUserSetWindowFNID        // Set window FNID (internal type identifier)
```

**GDI Operations:**
```c
NtGdiCreateBitmap          // Create bitmap (pool allocation)
NtGdiDeleteObjectApp       // Delete GDI object (pool deallocation)
NtGdiSetBitmapBits         // Write to bitmap (exploitation primitive)
NtGdiGetBitmapBits         // Read from bitmap (exploitation primitive)
NtGdiCreateRegion          // Create region (pool corruption target)
NtGdiSetDIBitsToDevice     // Set DIB bits (complex parameter validation)
NtGdiBitBlt                // Bit-block transfer (complex state machine)
NtGdiExtEscape             // Driver escape (driver communication)
NtGdiDrawEscape            // Draw escape (driver communication)
```

**Hook and Input Processing:**
```c
NtUserSetWindowsHookEx     // Install hook (HIGH RISK - code injection)
NtUserCallNextHookEx        // Call next hook in chain
NtUserUnhookWindowsHookEx   // Remove hook
NtUserSetTimer              // Set timer (callback hijacking)
NtUserKillTimer             // Kill timer
```

**Desktop and Window Station:**
```c
NtUserCreateWindowStation  // Create window station
NtUserCreateDesktop         // Create desktop
NtUserOpenWindowStation     // Open window station (privilege check)
NtUserOpenDesktop           // Open desktop (privilege check)
NtUserSetProcessWindowStation // Change process window station
```

---

## 7. Clipboard & DDE Attack Surface

### 7.1 Clipboard Architecture

The Windows clipboard is managed by Win32k and shared across all processes on a desktop. The clipboard architecture:

```c
// Clipboard data flow:
// 1. Source process calls SetClipboardData(format, hMem)
//    → Win32k copies or references the data
//    → Clipboard owns the data
//
// 2. Target process calls GetClipboardData(format)
//    → Win32k returns a handle to the clipboard data
//    → Target process can read the data
//
// 3. Clipboard formats:
//    CF_TEXT, CF_UNICODETEXT, CF_BITMAP, CF_DIB, CF_HDROP, CF_ENHMETAFILE,
//    CF_METAFILEPICT, CF_PRIVATEFIRST..CF_PRIVATELAST, CF_GDIOBJFIRST..CF_GDIOBJLAST
```

**Security implications:**

- **Cross-process data leakage**: Any process on the same desktop can read clipboard data. Clipboard monitoring applications can log everything copied.
- **Clipboard poisoning**: An attacker can write malicious data to the clipboard, which is then processed by the target application when the user pastes.
- **Delayed rendering**: `SetClipboardData(format, NULL)` registers a format without data. When a reader requests the format, the clipboard owner receives `WM_RENDERFORMAT`, allowing the owner to provide the data on demand. This creates a callback into the data provider when the data is requested.
- **GDI object injection**: `CF_BITMAP`, `CF_ENHMETAFILE`, and `CF_METAFILEPICT` clipboard formats transfer GDI objects between processes. Crafted GDI objects can trigger kernel vulnerabilities in the target process.

### 7.2 Dynamic Data Exchange (DDE)

DDE is a legacy inter-process communication mechanism that uses window messages:

```
DDE Protocol:
┌───────────┐                    ┌───────────┐
│  Client   │ ──WM_DDE_INITIATE─►│  Server   │
│           │◄─WM_DDE_ACK────────│           │
│           │                    │           │
│           │ ──WM_DDE_REQUEST──►│           │
│           │◄─WM_DDE_DATA──────│           │
│           │                    │           │
│           │ ──WM_DDE_EXECUTE──►│           │
│           │◄─WM_DDE_ACK────────│           │
│           │                    │           │
│           │ ──WM_DDE_TERMINATE►│           │
└───────────┘                    └───────────┘
```

DDE is a well-known attack vector:

- **DDE injection**: Sending `WM_DDE_EXECUTE` to a target window can cause the target application to execute commands. This was used in Office DDE attacks (CVE-2017-11882 and related).
- **DDE buffer overflow**: `WM_DDE_DATA` and `WM_DDE_POKE` messages carry data in global memory objects. If the target application doesn't validate buffer lengths, this can cause pool corruption in Win32k.
- **DDE conversation hijacking**: DDE conversations are identified by window handles, which can be enumerated and potentially hijacked.

---

## 8. Menu, Class & Hook Vulnerabilities

### 8.1 Menu Object Vulnerabilities

Menu objects (`HMENU`) are allocated from the paged pool and managed by Win32k. Menu structure internals:

```c
// Win32k internal menu structure (simplified)
typedef struct _MENU {
    HEAD     head;                  // Object header
    ULONG    fFlags;                // Menu flags
    INT      iItems;                // Number of menu items
    ULONG    cxMenu;                // Width
    ULONG    cyMenu;                // Height
    ULONG    cyMax;                 // Maximum item height
    ULONG    cxText;                // Maximum text width
    HFONT    hFont;                 // Menu font handle
    struct _ITEM *rgItems;          // Array of menu items (PAGED POOL)
    // ... more fields
} MENU, *PMENU;

typedef struct _ITEM {
    ULONG    fType;                 // Menu item type (MFT_STRING, MFT_BITMAP, etc.)
    ULONG    fState;                // Menu item state (MFS_ENABLED, MFS_CHECKED, etc.)
    UINT     uID;                   // Menu item ID
    HBITMAP  hbmpItem;             // Item bitmap handle
    ULONG    cch;                   // String length
    PWSTR    lpstr;                 // Item text (PAGED POOL allocation!)
    ULONG    cbItemData;            // Item data size
    PVOID    lpItemData;            // Item data pointer
    // ... more fields
} ITEM, *PITEM;
```

**Known menu vulnerability patterns:**

- **Menu item text overflow**: The `lpstr` field is allocated from paged pool. If the kernel doesn't properly validate the text length during `NtUserThunkedMenuItemInfo`, an attacker can overflow the text buffer.
- **Menu item data type confusion**: The `fType` field determines how `lpItemData` is interpreted. Type confusion between `MFT_OWNERDRAW` and `MFT_STRING` can lead to incorrect kernel pointer dereference.
- **Menu destruction during callback**: Destroying a menu while it's being processed (e.g., during `WM_INITMENUPOPUP`) can cause use-after-free on the `MENU` and `ITEM` structures.

### 8.2 Window Class Vulnerabilities

Window classes define the template for window creation:

```c
// Window class structure (WNDCLASSEX)
typedef struct _WNDCLASSEXA {
    UINT    cbSize;             // Structure size
    UINT    style;              // Class styles (CS_HREDRAW, CS_VREDRAW, etc.)
    WNDPROC lpfnWndProc;        // Window procedure (CRITICAL: user-mode callback)
    int     cbClsExtra;         // Extra class bytes (PAGED POOL allocation)
    int     cbWndExtra;         // Extra window bytes (PAGED POOL allocation)
    HINSTANCE hInstance;        // Module instance
    HICON   hIcon;              // Class icon
    HCURSOR hCursor;            // Class cursor
    HBRUSH  hbrBackground;      // Background brush
    LPCSTR  lpszMenuName;       // Menu resource name
    LPCSTR  lpszClassName;      // Class name string
} WNDCLASSEXA;
```

**Window class vulnerability patterns:**

- **`cbWndExtra` overflow**: If an attacker can control `cbWndExtra` and then write to the extra window bytes via `SetWindowLongPtr`, they can overflow the extra bytes buffer.
- **`lpfnWndProc` hijacking**: The `WNDPROC` pointer is stored in the kernel's `CLS` structure. If an attacker can modify this pointer (through pool corruption or type confusion), they control the callback destination.
- **Class atom pollution**: `RegisterClass` creates an atom in the global atom table. `GlobalFindAtom` can determine if a class is registered, and `UnregisterClass` can remove it. Manipulating the class registration state during window creation can cause type confusion.

### 8.3 Hook Vulnerabilities

Hook vulnerabilities arise from the complex lifecycle and re-entrancy of hook callbacks:

```c
// Hook callback flow:
// 1. Kernel identifies hook for current message
// 2. Kernel calls HOOKPROC via KeUserModeCallback
// 3. Hook procedure processes the message
// 4. Hook procedure may:
//    a. Call CallNextHookEx (continuing the chain)
//    b. Modify the message parameters
//    c. Install or uninstall hooks (CHANGING THE HOOK CHAIN!)
//    d. Destroy windows or GDI objects
// 5. Kernel continues processing with potentially modified chain
```

**Critical hook vulnerability: CVE-2016-0167 (Win32k EoP)**

```c
// Simplified vulnerability:
// The hook chain is implemented as a linked list:
// HOOKPROC(hook1) -> HOOKPROC(hook2) -> HOOKPROC(hook3) -> ...
//
// If hook2's callback removes hook1 from the chain,
// the kernel may still try to call hook1's callback,
// using a freed HOOK object → USE-AFTER-FREE

// Win32k hook dispatch (simplified):
PHOOK phk = phkFirstHook;
while (phk != NULL) {
    PHOOK phkNext = phk->phkNext;  // Save next pointer BEFORE callback
    xxxCallHookProc(phk, ...);      // Callback: can modify hook chain!
    phk = phkNext;                  // Use saved next pointer (safer)
    // But: phk->phkNext may still be stale if the chain was modified
}
```

---

## 9. CVE Analysis: CVE-2019-0808

### 9.1 Vulnerability Overview

**CVE-2019-0808** is a Win32k EoP vulnerability in the `win32k!xxxCreateWindowEx` function. It was exploited in the wild as part of a combined browser/kernel exploit chain targeting Internet Explorer on Windows 7.

| Attribute | Value |
|-----------|-------|
| **CVE** | CVE-2019-0808 |
| **Type** | Use-After-Free |
| **Component** | `win32k!xxxCreateWindowEx` |
| **Impact** | Elevation of Privilege (EoP) |
| **CVSS** | 7.8 |
| **Affected** | Windows 7 SP1, Windows Server 2008 R2 |
| **Attack Vector** | Local |
| **Privileges Required** | Low |
| **Exploit Complexity** | Medium |

### 9.2 Root Cause

The vulnerability is in the handling of `xxxCreateWindowEx` when creating a window with the `WS_MINIMIZE` style. During window creation, Win32k sends `WM_CREATE` and `WM_SIZE` messages to the new window's procedure. These callbacks allow user-mode code to execute, and during that execution, the window can be destroyed or invalidated.

```c
// Simplified vulnerable code path in xxxCreateWindowEx:
HWND xxxCreateWindowEx(...) {
    // Allocate window
    pwnd = HMallocObject(TYPE_WINDOW, ...);
    if (pwnd == NULL) return NULL;
    
    // Initialize window fields
    pwnd->style = style;
    pwnd->cbwndExtra = cbWndExtra;
    
    // Send WM_CREATE message (CALLBACK TO USER MODE!)
    lResult = xxxSendMessage(pwnd, WM_CREATE, ...);
    // At this point, pwnd may have been DESTROYED by the WM_CREATE handler
    
    if (pwnd->style & WS_MINIMIZE) {
        // USES pwnd AFTER potential free!
        // If WM_CREATE handler called DestroyWindow, pwnd is freed
        xxxSetWindowPos(pwnd, ...);  // USE-AFTER-FREE
        pwnd->style2 |= WS2_MINIMIZED;
    }
}
```

The specific trigger:
1. Create a window with `WS_MINIMIZE` style
2. In the `WM_CREATE` handler, destroy the window
3. When the callback returns, Win32k continues using the freed `pwnd` pointer

### 9.3 Exploitation

The exploitation of CVE-2019-0808 follows the classic pool feng shui pattern:

```
1. POOL SPRAY: Allocate many paged pool objects of the same size class
   as the WINDOW object to control pool layout
   
2. HOLE CREATION: Free selected pool objects to create predictable
   holes in the allocation pattern
   
3. TRIGGER: Create a window with WS_MINIMIZE style, and in the
   WM_CREATE handler, destroy the window. This frees the WINDOW
   object's pool allocation.
   
4. RECLAIM: Allocate a GDI object (e.g., bitmap) of the same size
   to reclaim the freed WINDOW object's memory. The GDI object's
   metadata now occupies the same memory as the freed WINDOW.
   
5. READ/WRITE: Use the dangling HWND to write to what it thinks
   is window extra bytes, but is actually GDI object metadata.
   This corrupts the GDI object's pvBits pointer, enabling
   arbitrary kernel read/write via SetBitmapBits/GetBitmapBits.
   
6. TOKEN REPLACEMENT: Read the current process token, locate
   SYSTEM process token, overwrite current process token with
   SYSTEM token → Local Privilege Escalation
```

### 9.4 Patch Analysis

The Microsoft patch added validation after the callback:

```c
// Patched code (simplified):
HWND xxxCreateWindowEx(...) {
    pwnd = HMallocObject(TYPE_WINDOW, ...);
    pwnd->style = style;
    
    lResult = xxxSendMessage(pwnd, WM_CREATE, ...);
    
    // PATCH: Validate that pwnd is still valid after callback
    if (HMIsMarkDestroy(pwnd)) {
        // Window was destroyed during callback
        return NULL;  // Don't use pwnd anymore
    }
    
    if (pwnd->style & WS_MINIMIZE) {
        xxxSetWindowPos(pwnd, ...);
    }
}
```

The key fix is checking `HMIsMarkDestroy(pwnd)` after every callback that could potentially destroy the window. This pattern (validate-after-callback) is the standard mitigation for Win32k re-entrancy bugs.

---

## 10. CVE Analysis: CVE-2020-0986

### 10.1 Vulnerability Overview

**CVE-2020-0986** is a Win32k EoP vulnerability caused by a use-after-free in the `win32k!xxxDestroyWindow` function, specifically in how window destruction handles sibling window references during callbacks.

| Attribute | Value |
|-----------|-------|
| **CVE** | CVE-2020-0986 |
| **Type** | Use-After-Free |
| **Component** | `win32k!xxxDestroyWindow` / `win32k!xxxFreeWindow` |
| **Impact** | Elevation of Privilege |
| **CVSS** | 7.8 |
| **Affected** | Windows 10 1903/1909/2004, Windows Server 1903/1909/2004 |
| **Exploit Complexity** | High |

### 10.2 Root Cause

When a window is destroyed, `xxxDestroyWindow` iterates through the window's property list and child windows, sending `WM_DESTROY` and `WM_NCDESTROY` messages. The vulnerability occurs because destroying a sibling or parent window during these callbacks can corrupt the window tree traversal:

```c
// Simplified xxxDestroyWindow flow:
void xxxDestroyWindow(PWND pwnd) {
    // Destroy child windows
    PWND pwndChild = pwnd->spwndChild;
    while (pwndChild != NULL) {
        PWND pwndNext = pwndChild->spwndNext;  // Save next BEFORE callback
        xxxFreeWindow(pwndChild, ...);           // CALLBACK: user-mode can
                                                 // destroy other windows here
        pwndChild = pwndNext;                    // pwndNext may be stale!
    }
    
    // Destroy window properties
    for (i = 0; i < pwnd->cWndProp; i++) {
        // Process property entries
        // If a previous callback freed properties, this is UAF
    }
}
```

The specific trigger:
1. Create a parent window with two child windows (Child A and Child B)
2. Set a property on Child A that triggers destruction of Child B during callback
3. Call `DestroyWindow` on the parent
4. When `xxxDestroyWindow` processes Child A's `WM_DESTROY`, the callback destroys Child B
5. When the loop continues to Child B, it's already freed → Use-After-Free

### 10.3 Exploitation Strategy

Exploiting CVE-2020-0986 on Windows 10 requires pool feng shui in the `Win32kPool` (separate from the general paged pool since RS1):

```
1. Create a parent window W with children C1, C2
2. Set a property on C1 with a callback that frees C2
3. Destroy W → xxxDestroyWindow processes C1 → callback frees C2
4. Reclaim C2's memory with a controlled allocation (GDI object)
5. Use C2's dangling handle to modify the reclaimed object
6. Achieve arbitrary kernel read/write through GDI bitmap primitive
7. Replace current process token with SYSTEM token
```

---

## 11. CVE Analysis: CVE-2021-1732

### 11.1 Vulnerability Overview

**CVE-2021-1732** is a Win32k EoP vulnerability in `win32k!xxxCreateWindowEx` that was exploited in the wild and publicly disclosed in February 2021. It is a callback-based use-after-free similar to CVE-2019-0808 but affecting a different code path.

| Attribute | Value |
|-----------|-------|
| **CVE** | CVE-2021-1732 |
| **Type** | Use-After-Free |
| **Component** | `win32k!xxxCreateWindowEx` / `xxxClientCreateWindowEx` |
| **Impact** | Elevation of Privilege |
| **CVSS** | 7.8 |
| **Affected** | Windows 10 1809, 1909, 2004, 20H2 |
| **Exploit Complexity** | Medium |

### 11.2 Root Cause

The vulnerability is in the window creation path where `xxxCreateWindowEx` calls `xxxClientCreateWindowEx` to send the `WM_CREATE` message. During this callback, `xxxClientCreateWindowEx` returns to user mode with the window's `CREATESTRUCT`. The kernel then processes the returned `CREATESTRUCT`, but the window may have been destroyed during the callback:

```c
// Simplified vulnerable code in xxxCreateWindowEx (Windows 10 2004):
HWND xxxCreateWindowEx(CREATESTRUCTW *pcs, ...) {
    // Allocate and initialize window
    pwnd = HMAllocObject(TYPE_WINDOW, ...);
    pwnd->cbwndExtra = pcs->cbWndExtra;
    
    // Send WM_CREATE via callback
    // The callback allows user-mode code to destroy the window
    lResult = xxxClientCreateWindowEx(pcs, pwnd, ...);
    
    // After callback, process the result
    // VULNERABILITY: pwnd may be freed, but code continues
    if (pwnd->cbwndExtra > 0) {
        // Write to extra window bytes
        // If pwnd is freed, this writes to freed memory
        RtlCopyMemory(pwnd + 1, pcs->lpCreateParams, 
                      min(pcs->cbWndExtra, pcs->cbClsExtra));
        // OVERFLOW: cbWndExtra from user mode can exceed allocated size
    }
}
```

The specific trigger sequence:
1. Register a window class with `cbWndExtra = 0x100`
2. Create a window with `cbWndExtra = 0x200` in the `CREATESTRUCT`
3. In the `WM_CREATE` handler, call `SetWindowLongPtr` to modify extra bytes
4. The kernel processes the oversized `cbWndExtra` after the callback, writing beyond the allocated extra bytes → **Pool Overflow**

Unlike CVE-2019-0808 (which is a pure UAF), CVE-2021-1732 is primarily a **pool overflow** caused by inconsistent validation of `cbWndExtra` between the allocation size and the post-callback copy.

### 11.3 Exploitation

The exploitation strategy for CVE-2021-1732 differs from traditional UAF because it's an overflow rather than a dangling pointer:

```
1. SPRAY: Allocate many GDI objects (bitmaps, regions) in paged pool
   to establish a controlled allocation pattern
   
2. HOLE: Create a hole in the spray by freeing a targeted object

3. TRIGGER: Create a window with cbWndExtra that overflows into
   the adjacent GDI object's metadata. The overflow modifies
   the adjacent object's size or pointer fields.

4. CONTROL: Use the corrupted GDI object to achieve arbitrary
   kernel read/write:
   - IfSURFOBJ.pvBits is overwritten → SetBitmapBits/GetBitmapBits primitive
   - If SURFOBJ.sizlBitmap is overwritten → size confusion primitive

5. ESCALATE: Read/write the current process's EPROCESS.Token
   to replace with SYSTEM token
```

---

## 12. CVE Analysis: CVE-2022-21882

### 12.1 Vulnerability Overview

**CVE-2022-21882** is a Win32k EoP vulnerability that bypassed the patch for CVE-2021-1732. The original patch added validation of `cbWndExtra` after the callback, but the validation was insufficient — it checked `pwnd->cbwndExtra` against the `CREATESTRUCT.cbWndExtra`, but a race condition allowed the check to be bypassed.

| Attribute | Value |
|-----------|-------|
| **CVE** | CVE-2022-21882 |
| **Type** | Pool Overflow (bypass of CVE-2021-1732 patch) |
| **Component** | `win32k!xxxCreateWindowEx` |
| **Impact** | Elevation of Privilege |
| **CVSS** | 7.8 |
| **Affected** | Windows 10 21H1, 21H2, Windows 11, Windows Server 2022 |
| **Exploit Complexity** | Medium |

### 12.2 Root Cause and Patch Bypass

The patch for CVE-2021-1732 added a check after the callback:

```c
// CVE-2021-1732 patch (simplified):
lResult = xxxClientCreateWindowEx(pcs, pwnd, ...);

// PATCH: Validate cbWndExtra after callback
if (pwnd->cbwndExtra != pcs->cbWndExtra) {
    // cbWndExtra was modified during callback
    pwnd->cbwndExtra = pcs->cbWndExtra;  // Reset to original value
    // OR: destroy the window
}
```

However, the bypass in CVE-2022-21882 exploited a subtle issue: the validation only checked `cbWndExtra` but not `cbClsExtra`. And more importantly, the validation occurred after `xxxClientCreateWindowEx` but before the window's extra bytes were initialized. An attacker could:

1. Create a window with a valid `cbWndExtra`
2. During the callback, modify the window class to change `cbClsExtra`
3. The post-callback code uses `cbClsExtra` in a different code path, causing an overflow

```c
// CVE-2022-21882 bypass mechanism:
// The patch validated cbWndExtra but NOT the total size calculation
// that includes cbClsExtra and cbWndExtra together.
// 
// Attack: Modify cbClsExtra during callback to increase the
// total extra bytes, causing overflow beyond the allocated buffer.

// Trigger:
// 1. Register class with cbClsExtra = 0x10, cbWndExtra = 0x10
// 2. Create window with those values
// 3. During WM_CREATE callback, modify class.cbClsExtra = 0x200
// 4. Post-callback code calculates offset into extra bytes using
//    the NOW-LARGER cbClsExtra, writing beyond the allocated buffer
```

### 12.3 Full Patch

The complete fix for both CVE-2021-1732 and CVE-2022-21882 adds comprehensive validation:

```c
// Final comprehensive patch:
lResult = xxxClientCreateWindowEx(pcs, pwnd, ...);

// Validate ALL size fields after callback:
if (pwnd->cbwndExtra != original_cbWndExtra ||
    pwnd->pcls->cbClsExtra != original_cbClsExtra) {
    // Window or class was modified during callback
    // Destroy the window to prevent any use-after-free or overflow
    xxxDestroyWindow(pwnd);
    return NULL;
}

// Validate total size:
if ((pwnd->cbwndExtra + pwnd->pcls->cbClsExtra) > allocated_size) {
    // Would overflow the extra bytes buffer
    xxxDestroyWindow(pwnd);
    return NULL;
}
```

This pattern — validate all sizes and states after any kernel-to-user callback — is the critical lesson from these Win32k vulnerabilities.

---

## 13. Win32k Exploitation Patterns

### 13.1 General Exploitation Methodology

A generic Win32k exploitation methodology:

```
PHASE 1: INFORMATION GATHERING
├── Determine Windows version and build
├── Identify Win32k pool allocation behavior
├── Map Win32k object sizes to allocation buckets
├── Identify GDI object spray quotas
└── Enumerate accessible window stations and desktops

PHASE 2: POOL SHAPING
├── Allocate objects in target size class
├── Create holes at predictable offsets
├── Verify pool layout with debug prints or side channels
└── Prepare GDI objects for read/write primitive

PHASE 3: TRIGGER
├── Execute vulnerability trigger (UAF, overflow, type confusion)
├── Corrupt adjacent or reclaimed object metadata
├── Convert corruption to controlled read/write
└── Verify primitive with probe reads

PHASE 4: PRIVILEGE ESCALATION
├── Locate current EPROCESS (PsGetCurrentProcess → EPROCESS)
├── Locate SYSTEM EPROCESS (Pid 4)
├── Read current token address
├── Overwrite current token with SYSTEM token (EX_FAST_REF)
├── Verify escalation (whoami /priv)
└── Clean up (restore pool layout if possible)
```

### 13.2 Win32k Pool Separation

Starting with Windows 10 RS1 (1607), Win32k objects are allocated from separate pools:

| Pool Type | Objects Allocated | Default State |
|-----------|-------------------|---------------|
| `Win32k!GdiPool` | GDI objects (bitmaps, regions, brushes) | Separate from general pool |
| `Win32k!UserPool` | USER objects (windows, menus, hooks) | Separate from general pool |
| `Win32k!DesktopPool` | Desktop objects | Separate from general pool |
| General paged pool | Non-Win32k objects | Yes |

This separation means that corrupting a GDI object's pool allocation no longer overflows into a `WINDOW` or `MENU` object, and vice versa. Exploits must target objects within the same pool, significantly increasing exploitation difficulty.

### 13.3 Win32k Tag Management

GDI objects have tag values that prevent handle reuse attacks:

```c
// GDI handle format (32-bit):
// Bits 31-16: Handle index (HINDEX)
// Bits 15-0:  Handle uniqueness tag (UNIQUE)
//
// When a GDI object is freed, the tag is incremented.
// This prevents stale handles from referencing newly allocated objects.
//
// However, if the attacker can predict or leak the tag value,
// they can construct valid handles to freed or reallocated objects.
//
// Win32k object type tags (used in pool allocation):
// 'Gh05' - HBITMAP (bitmap object)
// 'Gh08' - HPALETTE (palette object)
// 'Ghla' - HRGN (region object)
// 'Gh\0\x07' - HPEN (pen object)
// 'Usti' - Window station
// 'Usme' - Menu
// 'Uswi' - Window
```

### 13.4 Modern Exploitation Without GDI Primitive

With Win32k pool separation and HVCI (making the GDI bitmap read/write primitive less effective), modern Win32k exploits use alternative primitives:

**Pipe Attribute Primitive (Windows 10+):**
```c
// Named pipe attribute exploitation:
// 1. Create a named pipe
HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\exploit", ...);
// 2. Set pipe attributes to control kernel pool allocation
// 3. Use NtQueryInformationFile / NtSetInformationFile to read/write
//    pipe attributes → arbitrary kernel read/write
```

**Registry Key Primitive:**
```c
// Registry key exploitation:
// 1. Create a registry key
// 2. Set a value with controlled data
// 3. Trigger UAF that overwrites the registry key's cell data
// 4. Read/write the key value to achieve kernel read/write
```

**Token Swap Primitive:**
```c
// Direct token replacement:
// 1. Corrupt a process token pointer (EPROCESS.Token)
// 2. Overwrite with SYSTEM process token
// 3. Achieve privilege escalation without arbitrary read/write
```

---

## 14. Mitigations & Hardening

### 14.1 Win32k-Specific Mitigations

| Mitigation | Introduction | Effect |
|-----------|--------------|--------|
| **Win32k Pool Separation** | Win10 RS1 (1607) | Isolates GDI/USER pools from general paged pool |
| **Win32k Lock Order Enforcement** | Win10 RS2 (1703) | Validates lock acquisition order to prevent deadlocks and race conditions |
| **Win32k Reference Count Hardening** | Win10 RS3 (1709) | Reference count overflow/underflow detection |
| **Win32k Returned Pointer Validation** | Win10 RS4 (1803) | Validates pointers returned from callbacks |
| **Win32k Type Isolation** | Win10 RS5 (1809) | Further isolates object types within pools |
| **Win32k Callback Validation** | Win10 19H1 (1903) | Post-callback state validation (addresses CVE-2021-1732 class) |
| **HVCI** | Win10 RS1 (1607) | Prevents code execution in kernel from data pages |
| **KASLR** | Win8+ | Kernel address space randomization |
| **Pool Zeroing** | Win10+ | Freed pool allocations are zeroed (prevents info leak) |
| **Segment Heap** | Win10 19H1+ | Modern heap allocator with guard pages and encryption |

### 14.2 Exploit Mitigation Effectiveness

| Exploit Technique | Mitigated By | Bypass Difficulty |
|-------------------|-------------|-------------------|
| Classic GDI bitmap r/w | Pool separation, HVCI | Hard |
| Pool feng shui (paged pool) | Win32k pool separation | Medium (must use same-type objects) |
| Callback re-entrancy UAF | Callback validation | Hard (requires new code path) |
| Handle prediction | Pool zeroing, random tags | Medium |
| Pool overflow | Pool canaries (segment heap) | Medium |
| Type confusion | Type isolation | Hard |

### 14.3 Research Methodology

For discovering new Win32k vulnerabilities:

1. **Audit callback patterns**: Identify all `xxxSendMessage`, `xxxClientCreateWindowEx`, and `KeUserModeCallback` calls. After each callback, check for post-callback use of invalidated pointers.
2. **Fuzz Win32k syscalls**: Use a custom fuzzer that exercises the Win32k syscall table with valid but unusual parameters. Tools like `win32k-fuzz` and `kAFL` can target Win32k.
3. **Monitor Win32k object lifecycle**: Track all Win32k object creations/destructions and detect inconsistencies (double-free, use-after-free, reference count mismatch).
4. **Analyze WinDBK scripts**: Use `!heap -p -a <addr>` to detect pool corruption, `!object <addr>` to verify object state, `!win32k` extension commands for Win32k-specific debugging.
5. **Diff patches**: Analyze Microsoft's monthly patches for Win32k changes. New callback validation checks often indicate vulnerability classes similar to the fixed CVE.

---

> **Cross-references**:
> - Pool corruption details → `→ 03b_pool_corruption_exploitation`
> - NT kernel vulnerabilities → `→ 02b_nt_kernel_vulnerabilities`
> - Memory protections → `→ 03a_windows_memory_protections`
> - Advanced kernel exploitation → `→ 04b_advanced_kernel_exploitation`
> - OSEE Win32k questions → `→ OSEE` track
> - Linux kernel graphics comparison → `→ linux_kernel` track (DRM/GBM)

---

## References

1. Russinovich, M., Solomon, D., & Ionescu, A. *Windows Internals, Part 1*, 7th Edition. Microsoft Press, 2017. — Win32k subsystem architecture, GDI, and USER mode driver descriptions.
2. Morten, H. "Windows 10 Pool Overflow Exploitation." *Black Hat USA*, 2021. — Win32k GDI pool overflow primitives and exploitation.
3. Yason, M. "Windows Heap Exploitation." *Black Hat USA*, 2019. — Segment heap and GDI object pool allocation.
4. McGarr, C. "Win32k Type Confusion and Window Object Exploitation." *Connor McGarr's Blog*, 2022. — CVE-2021-1732 and CVE-2022-21882 deep dive.
5. National Vulnerability Database. CVE-2019-0808. "Win32k Elevation of Privilege." <https://nvd.nist.gov/vuln/detail/CVE-2019-0808>
6. National Vulnerability Database. CVE-2020-0986. "Win32k EoP — Callback Misuse." <https://nvd.nist.gov/vuln/detail/CVE-2020-0986>
7. National Vulnerability Database. CVE-2021-1732. "Win32k Type Confusion." <https://nvd.nist.gov/vuln/detail/CVE-2021-1732>
8. National Vulnerability Database. CVE-2022-21882. "Win32k Type Confusion." <https://nvd.nist.gov/vuln/detail/CVE-2022-21882>
9. Microsoft Security Response Center (MSRC) Blog. "Win32k Syscall Hardening and Attack Surface Reduction." <https://msrc.microsoft.com/blog/>
10. MITRE ATT&CK. "Exploitation for Privilege Escalation — T1068." <https://attack.mitre.org/techniques/T1068/>
11. Xia, J. "Analysis of Win32k System Calls." *Zero Day Initiative*, 2021. — Win32k syscall surface reduction efforts.
12. Microsoft Learn. "Win32k System Call Filtering." <https://learn.microsoft.com/en-us/windows/win32/api/winuser/> — Win32k API documentation.
13. Ormandy, T. "Win32k Attack Surface Analysis." *Google Project Zero*, 2017. — Comprehensive audit of Win32k callbacks and race conditions.
14. Chen, J. "The Old New Thing: Win32k Internals." <https://devblogs.microsoft.com/oldnewthing/> — Win32k design decisions and constraints.
15. DISA. "Windows 10 STIG — Win32k Hardening." <https://www.stigviewer.com/stigs/> — Win32k syscall restriction and callback hardening.