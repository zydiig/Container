import ctypes
import logging
import os
import re

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_NEWCGROUP = 0x02000000  # from include/uapi/linux/sched.h in Linux source code.

MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 262144

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def unshare(flags):
    if _libc.unshare(flags) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def sys_mount(*kargs):
    kargs = [(karg.encode("utf-8") if isinstance(karg, str) else karg) for karg in kargs]
    if _libc.mount(*kargs) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def sethostname(hostname: str):
    cstr = hostname.encode("utf-8")
    if _libc.sethostname(cstr, len(cstr)) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def chroot(path: str):
    if _libc.chroot(path.encode("utf-8")) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


# Inheritable pipes for IPC.
class Pipe:
    def __init__(self):
        self.r, self.w = os.pipe()
        os.set_inheritable(self.r, True)
        os.set_inheritable(self.w, True)

    def close_read(self):
        os.close(self.r)

    def close_write(self):
        os.close(self.w)

    def read(self, n):
        return os.read(self.r, n)

    def write(self, bs):
        os.write(self.w, bs)


def child(pipe1, pipe2, cgroup, ipc, mount, proc_path, pid, net, uts, user, uid_map, gid_map, cmd, hostname):
    """
    Requires to be root.
    User namespaces gives us a full set of caps, but that's too much of a hassle for me.
    """
    flags = 0
    if cgroup:
        flags |= CLONE_NEWCGROUP
    if ipc:
        flags |= CLONE_NEWIPC
    if mount:
        flags |= CLONE_NEWNS
    if pid:
        pass  # PID namespace has been unshared in the parent process.
    if net:
        flags |= CLONE_NEWNET
    if uts:
        flags |= CLONE_NEWUTS
    unshare(flags)
    if uts and hostname:
        sethostname(hostname)
    elif hostname:
        logging.warning("UTS namespace not enabled. Not setting hostname.")
    logging.debug("Child PID: {}".format(os.getpid()))
    if proc_path and pid:
        sys_mount("none", "/proc", None, MS_PRIVATE | MS_REC, None)
        sys_mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, None)
        if proc_path != "/proc":
            sys_mount("/proc", proc_path, None, MS_BIND, None)
        logging.debug("Mounted procfs at {}".format(proc_path))
    elif proc_path and not pid:
        logging.warning("PID namespace not enabled. Not mounting new procfs.")
    if user:
        logging.debug("User Namespace Enabled")
        # setgid and setuid to 'root' in the new user namespace.
        target_uid = 65534
        target_gid = 65534
        for uid_item in uid_map:
            in_start, out_start, length = [int(item) for item in re.split(" +", uid_item)]
            if in_start <= 0 < in_start + length:
                target_uid = out_start + (0 - in_start)
        for gid_item in gid_map:
            in_start, out_start, length = [int(item) for item in re.split(" +", gid_item)]
            if in_start <= 0 < in_start + length:
                target_gid = out_start + (0 - in_start)
        os.setgid(target_gid)
        os.setuid(target_uid)
        unshare(CLONE_NEWUSER)
    # signal parent to update maps.
    pipe1.write(b' ')
    # wait for parent to update mappings.
    pipe2.read(1)
    os.execvp(cmd[0], cmd)


def nsexec(**kwargs):
    pipe1 = Pipe()
    pipe2 = Pipe()
    if kwargs["pid"]:
        # calling unshare(CLONE_NEWPID) does not move the caller process into the new PID namespace, so we need to do this before forking.
        unshare(CLONE_NEWPID)
    pid = os.fork()
    if pid != 0:
        # Wait for child to unshare all namespaces.
        pipe1.read(1)
        logging.debug("Parent UID:{} eUID:{} GID:{} eGID:{}".format(os.getuid(), os.geteuid(), os.getgid(), os.getegid()))
        new_pid = pid
        if "uid_map" in kwargs:
            logging.debug("uid_map:{}".format(repr(kwargs["uid_map"])))
            with open("/proc/{}/uid_map".format(str(new_pid)), "wb") as f:
                f.write("\n".join(kwargs["uid_map"]).encode("utf-8"))
        if "gid_map" in kwargs:
            logging.debug("gid_map:{}".format(repr(kwargs["gid_map"])))
            with open("/proc/{}/gid_map".format(str(new_pid)), "wb") as f:
                f.write("\n".join(kwargs["gid_map"]).encode("utf-8"))
        logging.debug("Parent:Maps updated")
        os.setgid(1000)
        os.setuid(1000)
        pipe2.write(b' ')
        os.close(0)
        os.waitpid(pid, 0)
    else:
        child(pipe1, pipe2, **kwargs)
