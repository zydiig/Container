import ctypes
import logging
import os
import re
from functools import wraps
from uuid import uuid4

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_NEWCGROUP = 0x02000000  # from include/uapi/linux/sched.h in Linux source code.

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 262144
MS_STRICTATIME = 1 << 24

MNT_FORCE = 1
MNT_DETACH = 2
MNT_EXPIRE = 4
UMOUNT_NOFOLLOW = 8

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def require_root(fn):
    @wraps(fn)
    def wrapper(*kargs, **kwargs):
        if os.geteuid() != 0:
            raise Exception("Only root can do this.")
        return fn(*kargs, **kwargs)

    return wrapper


def sys_unshare(flags):
    if _libc.unshare(flags) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


@require_root
def sys_mount(*kargs):
    logging.debug(repr(kargs))
    kargs = [(karg.encode("utf-8") if isinstance(karg, str) else karg) for karg in kargs]
    if _libc.mount(*kargs) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


@require_root
def sys_umount(target, flags=0):
    target = target.encode("utf-8")
    if _libc.umount2(target, flags) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


@require_root
def sethostname(hostname: str):
    cstr = hostname.encode("utf-8")
    if _libc.sethostname(cstr, len(cstr)) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


class Pipe:
    """Inheritable pipes for IPC"""

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


def translate(idx, mappings):
    for item in mappings:
        original_base, translated_base, length = [int(item) for item in re.split(" +", item)]
        if original_base <= idx <= original_base + length - 1:
            return translated_base + (idx - original_base)


def child(pipe1, pipe2, cmd, root_path, flags, pid, user, uid_map, gid_map, hostname, env):
    """
    Requires root privilege.
    User namespaces gives us a full set of caps, but that's too much of a hassle for me.
    """
    sys_unshare(flags)
    if flags & CLONE_NEWUTS and hostname:
        sethostname(hostname)
    elif hostname:
        logging.warning("UTS namespace not enabled. Not setting hostname.")
    logging.debug("Child PID: {}".format(os.getpid()))
    if pid:  # CLONE_NEWPID is not included in flags. Also we need to mount a new procfs to reflect the newly created PID namespace.
        sys_mount("proc", os.path.join(root_path, "proc"), "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, None)
    else:
        logging.warning("PID namespace is disabled. {}".format(pid))
    if user:
        logging.debug("User namespace is enabled.")
        # setgid and setuid to 'root' in the new user namespace.
        target_uid = translate(0, uid_map) or 65534
        target_gid = translate(0, gid_map) or 65534
        if target_gid == 65534 or target_uid == 65534:
            logging.warning("The mappings does not covered UID 0 and GID 0.")
        os.setgid(target_gid)
        os.setuid(target_uid)
        sys_unshare(CLONE_NEWUSER)
    # signal parent to update maps.
    pipe1.write(b' ')
    # wait for parent to update mappings.
    pipe2.read(1)
    os.chroot(root_path)
    os.chdir("/")  # per chroot(2) manpage.
    os.execvpe(cmd[0], cmd, env)


def run_in_new_process(fn):
    @wraps(fn)
    def wrapper(*kargs, **kwargs):
        pid = os.fork()
        if pid == 0:
            fn(*kargs, **kwargs)
            exit(0)
        else:
            os.waitpid(pid, 0)

    return wrapper


@require_root
def add_to_cgroup(pid, specs):
    uuid = str(uuid4())
    paths = []
    if "cpuset" in specs:
        os.mkdir("/sys/fs/cgroup/cpuset/{}".format(uuid))
        with open("/sys/fs/cgroup/cpuset/{}/cpuset.cpus".format(uuid), "w") as f:
            f.write(",".join([str(i) for i in specs["cpuset"]]))
        with open("/sys/fs/cgroup/cpuset/{}/cpuset.mems".format(uuid), "w") as f:
            f.write("0")
        with open("/sys/fs/cgroup/cpuset/{}/tasks".format(uuid), "w") as f:
            f.write(str(pid))
        paths.append("/sys/fs/cgroup/cpuset/{}".format(uuid))
    if "memory" in specs:
        os.mkdir("/sys/fs/cgroup/memory/{}".format(uuid))
        with open("/sys/fs/cgroup/memory/{}/memory.limit_in_bytes".format(uuid), "w") as f:
            f.write(specs["memory"]["physical"])
        with open("/sys/fs/cgroup/memory/{}/memory.memsw.limit_in_bytes".format(uuid), "w") as f:
            f.write(specs["memory"]["with_swap"])
        with open("/sys/fs/cgroup/memory/{}/tasks".format(uuid), "w") as f:
            f.write(str(pid))
        paths.append("/sys/fs/cgroup/memory/{}".format(uuid))
    return paths


@run_in_new_process
def start_container(cmd, root_path, cgroup=True, ipc=True, mount=True, pid=True, net=False, uts=True, user=True, uid_map=None, gid_map=None,
                    hostname="CONTAINER", env={}, cgroup_specs={}):
    pipe1 = Pipe()
    pipe2 = Pipe()
    flags = 0
    if cgroup:
        flags |= CLONE_NEWCGROUP
    if ipc:
        flags |= CLONE_NEWIPC
    if mount:
        flags |= CLONE_NEWNS
    if net:
        flags |= CLONE_NEWNET
    if uts:
        flags |= CLONE_NEWUTS
    if pid:
        # calling unshare(CLONE_NEWPID) does not move the caller process into the new PID namespace, so we need to do this in advance.
        sys_unshare(CLONE_NEWPID)
    child_pid = os.fork()
    if child_pid != 0:
        cgroup_paths = add_to_cgroup(child_pid, cgroup_specs)
        # Wait for child to unshare user namespaces before updating relevant mappings.
        pipe1.read(1)
        if user:
            if uid_map:
                logging.debug("uid_map:{}".format(repr(uid_map)))
                with open("/proc/{}/uid_map".format(str(child_pid)), "wb") as f:
                    f.write("\n".join(uid_map).encode("utf-8"))
            if gid_map:
                logging.debug("gid_map:{}".format(repr(gid_map)))
                with open("/proc/{}/gid_map".format(str(child_pid)), "wb") as f:
                    f.write("\n".join(gid_map).encode("utf-8"))
            logging.debug("Parent:Maps updated")
        pipe2.write(b' ')
        os.close(0)
        os.waitpid(child_pid, 0)
        sys_umount(os.path.join(root_path, "proc"))
        for path in cgroup_paths:
            os.rmdir(path)
    else:
        child(pipe1, pipe2, cmd, root_path, flags, pid, user, uid_map, gid_map, hostname, env)
