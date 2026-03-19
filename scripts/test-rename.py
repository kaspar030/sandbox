#!/usr/bin/env python3
"""Test rename operations on idmapped mounts in user namespaces.

Usage:
    sudo python3 scripts/test-rename.py <container-pid>

Tests:
1. Plain rename() via /proc/pid/root/
2. renameat2(flags=0) via /proc/pid/root/
3. renameat2(RENAME_NOREPLACE) via /proc/pid/root/
4. Plain rename inside container via nsenter
5. Check on-disk UIDs of test files
"""

import os
import sys
import ctypes
import subprocess

libc = ctypes.CDLL("libc.so.6", use_errno=True)

SYS_renameat2 = 316  # x86_64
AT_FDCWD = -100
RENAME_NOREPLACE = 1


def errno_str():
    e = ctypes.get_errno()
    return f"errno={e} ({os.strerror(e)})"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <container-pid>")
        sys.exit(1)

    pid = int(sys.argv[1])
    print(f"Container PID: {pid}")
    print()

    # Setup: create test files inside the container
    print("=== Setup: creating test files via nsenter ===")
    for name in ["rename_plain", "rename_at2_0", "rename_at2_noreplace", "rename_nsenter"]:
        subprocess.run(
            ["nsenter", "--user", "--mount", f"--target={pid}", "--",
             "touch", f"/tmp/{name}"],
            capture_output=True
        )
    print("OK")
    print()

    # Check on-disk UIDs
    print("=== On-disk UIDs (raw, no idmap) ===")
    # Find the container's rootfs path
    rootfs_candidates = []
    for pool_dir in ["/var/lib/sandbox/storage/main/fs"]:
        if os.path.isdir(pool_dir):
            for entry in os.listdir(pool_dir):
                rootfs_candidates.append(os.path.join(pool_dir, entry))

    for candidate in rootfs_candidates:
        test_file = os.path.join(candidate, "tmp/rename_plain")
        if os.path.exists(test_file):
            st = os.stat(test_file)
            print(f"  Raw rootfs: {candidate}")
            print(f"  /tmp/rename_plain: uid={st.st_uid} gid={st.st_gid}")
            # Check /etc/timezone too
            tz = os.path.join(candidate, "etc/timezone")
            if os.path.exists(tz):
                st2 = os.stat(tz)
                print(f"  /etc/timezone: uid={st2.st_uid} gid={st2.st_gid}")
            break
    print()

    # Check UIDs through /proc/pid/root (idmapped)
    print("=== UIDs through /proc/pid/root (idmapped) ===")
    proc_root = f"/proc/{pid}/root"
    for path in ["tmp/rename_plain", "etc/timezone"]:
        full = os.path.join(proc_root, path)
        if os.path.exists(full):
            st = os.stat(full)
            print(f"  {path}: uid={st.st_uid} gid={st.st_gid}")
    print()

    # Test 1: plain rename() via /proc/pid/root
    print("=== Test 1: rename() via /proc/pid/root ===")
    src = f"/proc/{pid}/root/tmp/rename_plain"
    dst = f"/proc/{pid}/root/tmp/rename_plain_done"
    try:
        os.rename(src, dst)
        print(f"  OK")
    except OSError as e:
        print(f"  FAIL: {e}")
    print()

    # Test 2: renameat2(flags=0) via /proc/pid/root
    print("=== Test 2: renameat2(flags=0) via /proc/pid/root ===")
    src = f"/proc/{pid}/root/tmp/rename_at2_0".encode() + b"\x00"
    dst = f"/proc/{pid}/root/tmp/rename_at2_0_done".encode() + b"\x00"
    r = libc.syscall(SYS_renameat2, AT_FDCWD, src, AT_FDCWD, dst, 0)
    if r == 0:
        print("  OK")
    else:
        print(f"  FAIL: {errno_str()}")
    print()

    # Test 3: renameat2(RENAME_NOREPLACE) via /proc/pid/root
    print("=== Test 3: renameat2(RENAME_NOREPLACE) via /proc/pid/root ===")
    src = f"/proc/{pid}/root/tmp/rename_at2_noreplace".encode() + b"\x00"
    dst = f"/proc/{pid}/root/tmp/rename_at2_noreplace_done".encode() + b"\x00"
    r = libc.syscall(SYS_renameat2, AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE)
    if r == 0:
        print("  OK")
    else:
        print(f"  FAIL: {errno_str()}")
    print()

    # Test 4: rename inside container via nsenter
    print("=== Test 4: rename inside container via nsenter (perl) ===")
    r = subprocess.run(
        ["nsenter", "--user", "--mount", f"--target={pid}", "--",
         "perl", "-e", 'rename("/tmp/rename_nsenter", "/tmp/rename_nsenter_done") or die "rename: $!\\n"'],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        print("  OK (plain rename via perl)")
    else:
        stderr = r.stderr.strip()
        print(f"  FAIL: {stderr}")
        # If perl not available, try mv
        if "No such file" in stderr or "not found" in stderr:
            print("  perl not available, trying mv...")
            r = subprocess.run(
                ["nsenter", "--user", "--mount", f"--target={pid}", "--",
                 "mv", "/tmp/rename_nsenter", "/tmp/rename_nsenter_done"],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                print("  OK (mv)")
            else:
                print(f"  FAIL: {r.stderr.strip()}")
    print()

    # Test 5: renameat2 inside container via fork+setns (same as container process)
    print("=== Test 5: renameat2 inside container via fork+setns ===")
    # Create fresh test files
    subprocess.run(
        ["nsenter", "--user", "--mount", f"--target={pid}", "--",
         "touch", "/tmp/rename_setns_plain", "/tmp/rename_setns_noreplace"],
        capture_output=True
    )

    child = os.fork()
    if child != 0:
        _, status = os.waitpid(child, 0)
        code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
        if code != 0:
            print(f"  Child exited with code {code}")
    else:
        # Enter container namespaces (same as our hot_mount approach)
        user_fd = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY)
        libc.setns(user_fd, 0x10000000)  # CLONE_NEWUSER
        os.close(user_fd)

        mnt_fd = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
        libc.setns(mnt_fd, 0x00020000)  # CLONE_NEWNS
        os.close(mnt_fd)

        libc.syscall(119, 0, 0, 0)  # setresgid
        libc.syscall(117, 0, 0, 0)  # setresuid

        os.chroot("/")
        os.chdir("/")

        print(f"  uid={os.getuid()} gid={os.getgid()}")

        # Plain rename
        src = b"/tmp/rename_setns_plain\x00"
        dst = b"/tmp/rename_setns_plain_done\x00"
        r = libc.syscall(SYS_renameat2, AT_FDCWD, src, AT_FDCWD, dst, 0)
        if r == 0:
            print("  renameat2(flags=0) inside container: OK")
        else:
            print(f"  renameat2(flags=0) inside container: FAIL {errno_str()}")

        # NOREPLACE
        src = b"/tmp/rename_setns_noreplace\x00"
        dst = b"/tmp/rename_setns_noreplace_done\x00"
        r = libc.syscall(SYS_renameat2, AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE)
        if r == 0:
            print("  renameat2(RENAME_NOREPLACE) inside container: OK")
        else:
            print(f"  renameat2(RENAME_NOREPLACE) inside container: FAIL {errno_str()}")

        os._exit(0)

    print()
    print("=== Summary ===")
    print("If tests 1-3 fail but test 5 works: the issue is with /proc/pid/root access")
    print("If test 5 plain rename works but NOREPLACE fails: kernel bug in NOREPLACE + idmap")
    print("If both test 5 renames fail: fundamental idmap issue with rename")


if __name__ == "__main__":
    main()
