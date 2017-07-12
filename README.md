Container
==============
Simple containers implemented in Python 3.

**May not actually contain things**

An example configuration file is included as `example.yaml`.

Features
---------------
- PID namespaces
- User namespaces
- YAML configuration files
- Custom environment variables
- Features can be turned on/off (not tested)

TODOs
---------
- Move mounting-related code out from contain.py
- Custom bind mounts ([bindfs](http://bindfs.org/) to change permissions or ownership?)
- PTY support for shells inside containers
- More customizable
- Support for starting `init` (`systemd`?) inside containers
- Automatic Xauth

Notes
----------------
- File and directory ownership is not handled by this program. If you use user namespaces, remember to chown your new root directory.
- `/dev` `/sys` or `/dev/pts` are not writable by 'root' inside the container. Use [bindfs](http://bindfs.org/) to workaround this, though what's the point of enabling user namespace if you want to do that?
- Some programs, such as `sudo` or `su` may not function correctly without PTY support.
- `/etc/profile` etc. won't be sourced in the new shell. You'll need to do it yourself.