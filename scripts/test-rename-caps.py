#!/usr/bin/env python3
"""Bisect which Linux capability makes renameat2(RENAME_NOREPLACE) work on idmapped mounts.

Usage:
    sudo python3 scripts/test-rename-caps.py <container-pid>

Forks a child for each test. Each child enters the container's namespaces,
drops capabilities to a specific set, and tries renameat2(RENAME_NOREPLACE).
"""

import os
import sys
import ctypes
import struct

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# Syscall numbers (x86_64)
SYS_renameat2 = 316
SYS_capset = 125
SYS_capget = 124
SYS_setresuid = 117
SYS_setresgid = 119
AT_FDCWD = -100
RENAME_NOREPLACE = 1
CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
PR_CAPBSET_DROP = 24
PR_CAPBSET_READ = 23

# All Linux capabilities (as of kernel 6.x)
ALL_CAPS = {
    0:  "CAP_CHOWN",
    1:  "CAP_DAC_OVERRIDE",
    2:  "CAP_DAC_READ_SEARCH",
    3:  "CAP_FOWNER",
    4:  "CAP_FSETID",
    5:  "CAP_KILL",
    6:  "CAP_SETGID",
    7:  "CAP_SETUID",
    8:  "CAP_SETPCAP",
    9:  "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

# Docker default capability set (14 caps)
DOCKER_DEFAULTS = {
    0,   # CAP_CHOWN
    1,   # CAP_DAC_OVERRIDE
    3,   # CAP_FOWNER
    4,   # CAP_FSETID
    5,   # CAP_KILL
    6,   # CAP_SETGID
    7,   # CAP_SETUID
    8,   # CAP_SETPCAP
    10,  # CAP_NET_BIND_SERVICE
    13,  # CAP_NET_RAW
    18,  # CAP_SYS_CHROOT
    27,  # CAP_MKNOD
    29,  # CAP_AUDIT_WRITE
    31,  # CAP_SETFCAP
}


def caps_to_u64(cap_set):
    """Convert a set of capability bits to a u64 bitmask."""
    val = 0
    for bit in cap_set:
        val |= (1 << bit)
    return val


def errno_str():
    e = ctypes.get_errno()
    return f"errno={e} ({os.strerror(e)})"


# capset/capget structures
class CapHeader(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]

class CapData(ctypes.Structure):
    _fields_ = [
        ("effective_lo", ctypes.c_uint32),
        ("permitted_lo", ctypes.c_uint32),
        ("inheritable_lo", ctypes.c_uint32),
        ("effective_hi", ctypes.c_uint32),
        ("permitted_hi", ctypes.c_uint32),
        ("inheritable_hi", ctypes.c_uint32),
    ]


def apply_caps(cap_set):
    """Drop caps from bounding set and set effective/permitted to cap_set."""
    mask = caps_to_u64(cap_set)

    # Drop caps not in our set from the bounding set
    for bit in range(41):
        if bit not in cap_set:
            r = libc.prctl(PR_CAPBSET_DROP, bit, 0, 0, 0)
            # Ignore errors for caps that don't exist on this kernel

    # Use capset to set effective and permitted
    header = CapHeader()
    header.version = 0x20080522  # _LINUX_CAPABILITY_VERSION_3
    header.pid = 0  # current process

    data = CapData()
    lo = mask & 0xFFFFFFFF
    hi = (mask >> 32) & 0xFFFFFFFF
    data.effective_lo = lo
    data.permitted_lo = lo
    data.inheritable_lo = 0
    data.effective_hi = hi
    data.permitted_hi = hi
    data.inheritable_hi = 0

    r = libc.syscall(SYS_capset, ctypes.byref(header), ctypes.byref(data))
    if r != 0:
        return False
    return True


def test_rename_with_caps(pid, cap_set, test_name, file_suffix):
    """Fork a child, enter container ns, apply caps, try renameat2(RENAME_NOREPLACE)."""
    child = os.fork()
    if child != 0:
        _, status = os.waitpid(child, 0)
        return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0

    # === CHILD ===
    try:
        # Enter container namespaces
        user_fd = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY)
        libc.setns(user_fd, CLONE_NEWUSER)
        os.close(user_fd)

        mnt_fd = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
        libc.setns(mnt_fd, CLONE_NEWNS)
        os.close(mnt_fd)

        libc.syscall(SYS_setresgid, 0, 0, 0)
        libc.syscall(SYS_setresuid, 0, 0, 0)

        # Apply capability set BEFORE chroot
        if not apply_caps(cap_set):
            os._exit(2)  # capset failed

        os.chroot("/")
        os.chdir("/tmp")

        # Create test file
        src = f"captest_{file_suffix}".encode() + b"\x00"
        dst = f"captest_{file_suffix}_done".encode() + b"\x00"

        # Touch the source file
        fd = os.open(f"/tmp/captest_{file_suffix}", os.O_CREAT | os.O_WRONLY, 0o644)
        os.close(fd)

        # Try renameat2(RENAME_NOREPLACE)
        r = libc.syscall(SYS_renameat2, AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE)
        if r == 0:
            os._exit(0)  # success
        else:
            os._exit(1)  # EPERM or other error

    except Exception:
        os._exit(3)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <container-pid>")
        sys.exit(1)

    pid = int(sys.argv[1])
    print(f"Container PID: {pid}")
    print()

    # Test 1: Baseline — Docker defaults only
    print("=== Baseline: Docker-default 14 caps ===")
    ok = test_rename_with_caps(pid, DOCKER_DEFAULTS, "docker_defaults", "baseline")
    print(f"  renameat2(RENAME_NOREPLACE): {'OK' if ok else 'FAIL (EPERM)'}")
    if ok:
        print("  Rename works with Docker defaults — no additional cap needed!")
        sys.exit(0)
    print()

    # Test 2: All caps
    print("=== All capabilities ===")
    all_caps = set(ALL_CAPS.keys())
    ok = test_rename_with_caps(pid, all_caps, "all_caps", "allcaps")
    print(f"  renameat2(RENAME_NOREPLACE): {'OK' if ok else 'FAIL'}")
    if not ok:
        print("  ERROR: Rename fails even with all caps — not a capability issue!")
        sys.exit(1)
    print()

    # Test 3: Bisect — add each missing cap individually
    missing_caps = sorted(all_caps - DOCKER_DEFAULTS)
    print(f"=== Testing {len(missing_caps)} missing capabilities individually ===")
    print()

    fixes = []
    for cap_bit in missing_caps:
        cap_name = ALL_CAPS[cap_bit]
        test_set = DOCKER_DEFAULTS | {cap_bit}
        ok = test_rename_with_caps(pid, test_set, cap_name, f"cap{cap_bit}")
        status = "OK <<<" if ok else "FAIL"
        print(f"  + {cap_name:<30} (bit {cap_bit:>2}): {status}")
        if ok:
            fixes.append((cap_bit, cap_name))

    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    if fixes:
        print(f"Adding ANY of these caps fixes renameat2(RENAME_NOREPLACE):")
        for bit, name in fixes:
            print(f"  {name} (bit {bit})")
        print()
        print("Recommendation: add the least-privileged one to the default set.")
    else:
        print("No single cap fixes the issue — may require a combination.")
        print("This would require more complex bisection.")


if __name__ == "__main__":
    main()
