import os
import sys
from subprocess import call

import yaml

import nsexec


def mount(types, source, target, mount_options=[], extra_options=[]):
    if os.geteuid() != 0:
        raise Exception("Only root can do this.")
    cmd = ["mount", source, target, "-o", ",".join(mount_options), "-t", types] + extra_options
    if call(cmd) != 0:
        print("Execution of command failed:", " ".join(cmd))


def umount(target, options=[]):
    if os.geteuid() != 0:
        raise Exception("Only root can do this.")
    cmd = ["umount", target] + options
    if call(cmd) != 0:
        print("Execution of command failed:", " ".join(cmd))


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) == 2 else "default.yaml"
    config = yaml.load(open(target))
    print(config)
    root_path = config["specs"]["root_path"]
    mounts = [
        ("sysfs", "sys", os.path.join(root_path, "sys"), ["nosuid", "noexec", "nodev", "ro"]),
        ("devtmpfs", "udev", os.path.join(root_path, "dev"), ["mode=0755", "nosuid"]),
        ("devpts", "devpts", os.path.join(root_path, "dev/pts"), ["mode=0620", "gid=5", "nosuid", "noexec"]),
        ("tmpfs", "shm", os.path.join(root_path, "dev/shm"), ["mode=1777", "nosuid", "nodev"]),
        ("tmpfs", "run", os.path.join(root_path, "run"), ["nosuid", "nodev", "mode=0755", "uid=100000", "gid=100000"]),
        ("tmpfs", "tmp", os.path.join(root_path, "tmp"), ["mode=1777", "strictatime", "nodev", "nosuid"])
    ]
    for mount_ops in mounts:
        mount(*mount_ops)
    pid = os.fork()
    if pid == 0:
        nsexec.nsexec(**config["features"], proc_path=config["specs"]["proc_path"],
                      uid_map=config["specs"]["uid_map"], gid_map=config["specs"]["gid_map"], cmd=["bash", "./chroot.sh", root_path],
                      hostname="CONTAINER")
    else:
        os.waitpid(pid, 0)
        umount(config["proc_path"])
        for mount_ops in reversed(mounts):
            umount(mount_ops[2])
            # if not call('nsexec2 -C -i -m -p -u -U -P "/opt/testroot/proc" -M "0 100000 65536" -G "0 100000 65536" bash ./chroot.sh', shell=True):
            #     pass
