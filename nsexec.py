import argparse
import ctypes
import logging
import os

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_NEWCGROUP = 0x02000000

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
    if _libc.mount(*kargs) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def sethostname(hostname: str):
    cstr = hostname.encode("utf-8")
    if _libc.sethostname(cstr, len(cstr)) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


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
    User namespacing gives us a full set of caps, but that's too much of a hassle for me.
    """
    flags = 0
    if cgroup:
        flags |= CLONE_NEWCGROUP
    if ipc:
        flags |= CLONE_NEWIPC
    if mount:
        flags |= CLONE_NEWNS
    if pid:
        # PID namespace has been unshared in parent process.
        flags |= 0
    if net:
        flags |= CLONE_NEWNET
    if uts:
        flags |= CLONE_NEWUTS
    unshare(flags)
    if uts:
        sethostname(hostname)
    logging.debug("Child PID: {}".format(os.getpid()))
    if proc_path:
        sys_mount(b"none", b"/proc", None, MS_PRIVATE | MS_REC, None)
        sys_mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, None)
        if proc_path != "/proc":
            sys_mount(b"/proc", proc_path.encode("utf-8"), None, MS_BIND, None)
        logging.debug("Mounted procfs at {}".format(proc_path))
    # setuid to 'root' in the new user namespace.
    os.setgid(100000)
    os.setuid(100000)
    if user:
        unshare(CLONE_NEWUSER)
        logging.debug("User Namespace Enabled")
    # signal parent to update maps.
    pipe1.write(b' ')
    # wait for parent to update mappings.
    pipe2.read(1)
    logging.debug("Child:Maps updated")
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
        logging.debug("Waiting for child to unshare ns")
        pipe1.read(1)
        logging.debug("Parent UID:{} eUID:{}".format(os.getuid(), os.geteuid()))
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
    else:  # forked child
        child(pipe1, pipe2, **kwargs)