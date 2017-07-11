import logging
import os
import sys
from subprocess import call

import yaml

import namespace

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)


def require_root(fn):
    def wrapper():
        if os.geteuid() != 0:
            raise Exception("Only root can do this.")
        fn()

    return wrapper


@require_root
def mount(types, source, target, mount_options=[], extra_options=[]):
    cmd = ["mount", source, target, "-o", ",".join(mount_options), "-t", types] + extra_options
    if call(cmd) != 0:
        print("Execution of command failed:", " ".join(cmd))


@require_root
def umount(target, options=[]):
    cmd = ["umount", target] + options
    if call(cmd) != 0:
        print("Execution of command failed:", " ".join(cmd))


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) == 2 else "default.yaml"
    config = yaml.load(open(target))
    root_path = config["specs"]["root_path"]
    t_uid = namespace.translate(0, config["specs"]["uid_map"])
    t_gid = namespace.translate(0, config["specs"]["gid_map"])
    mounts = [
        ("sysfs", "sys", os.path.join(root_path, "sys"), ["nosuid", "noexec", "nodev", "ro"]),
        ("devtmpfs", "udev", os.path.join(root_path, "dev"), ["mode=0755", "nosuid"]),
        ("devpts", "devpts", os.path.join(root_path, "dev/pts"), ["mode=0620", "gid=5", "nosuid", "noexec"]),
        ("tmpfs", "shm", os.path.join(root_path, "dev/shm"), ["mode=1777", "nosuid", "nodev"]),
        ("tmpfs", "run", os.path.join(root_path, "run"), ["nosuid", "nodev", "mode=0755", "uid={}".format(t_uid), "uid={}".format(t_gid)]),
        ("tmpfs", "tmp", os.path.join(root_path, "tmp"), ["mode=1777", "strictatime", "nodev", "nosuid"])
    ]
    for mount_ops in mounts:
        mount(*mount_ops)
    pid = os.fork()
    if pid == 0:
        namespace.start_container(config["specs"]["command"].split(" "), root_path, **config["features"],
                                  uid_map=config["specs"]["uid_map"], gid_map=config["specs"]["gid_map"],
                                  hostname=config["specs"]["hostname"])
    else:
        os.waitpid(pid, 0)
        for mount_ops in reversed(mounts):
            umount(mount_ops[2])
