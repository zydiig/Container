#!/usr/bin/python3

import argparse

import yaml
import traceback

from namespace import *


@require_root
def mount(fstype, source, target, flags=0, mount_options=[]):
    sys_mount(source, target, fstype, flags, ",".join(mount_options))


def try_unmount_all(l):
    for target in l:
        try:
            sys_umount(target)
        except OSError:
            logging.error("Unmounting {} failed.".format(target))
            logging.error(traceback.format_exc())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Starts a simple container.")
    parser.add_argument("path", help="Path to the container specification file", metavar="CFG")
    parser.add_argument("--verbose", "-v", help="Verbose mode", action="store_true", dest="verbose")
    args = parser.parse_args()
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG if args.verbose else logging.INFO)
    config = yaml.load(open(args.path))
    specs = config["specs"]
    root_path = specs["root_path"]
    if config["features"].get("user", True):
        t_uid = translate(0, specs["uid_map"])
        t_gid = translate(0, specs["gid_map"])
    else:
        t_uid = 0
        t_gid = 0
    mounts = [
        ("sysfs", "sys", os.path.join(root_path, "sys"), MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY,[]),
        ("devtmpfs", "udev", os.path.join(root_path, "dev"), MS_NOSUID, ["mode=0755"]),
        ("devpts", "devpts", os.path.join(root_path, "dev/pts"), MS_NOEXEC | MS_NOSUID, ["mode=0620", "gid=5"]),
        ("tmpfs", "shm", os.path.join(root_path, "dev/shm"), MS_NOSUID | MS_NODEV, ["mode=1777"]),
        ("tmpfs", "run", os.path.join(root_path, "run"), MS_NOSUID | MS_NODEV, ["mode=0755", "uid={}".format(t_uid), "gid={}".format(t_gid)]),
        ("tmpfs", "tmp", os.path.join(root_path, "tmp"), MS_STRICTATIME | MS_NODEV | MS_NOSUID, ["mode=1777"])
    ]
    for mount_ops in mounts:
        try:
            mount(*mount_ops)
        except OSError as e:
            logging.debug(repr(mount_ops))
            logging.error(traceback.format_exc())
            try_unmount_all([mount_ops[2] for mount_ops in mounts])
            exit(1)
    start_container(specs["command"].split(" "), root_path, **config["features"], uid_map=specs.get("uid_map", ""),
                    gid_map=specs.get("gid_map", ""), hostname=specs.get("hostname", "CONTAINER"), env=config.get("env", {}),
                    cgroup_specs=config.get("cgroups", {}))
    try_unmount_all(reversed([mount_ops[2] for mount_ops in mounts]))