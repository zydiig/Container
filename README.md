Container
==============
Simple containers implemented in Python 3.

**May not actually contain things**

Features
---------------
- PID namespaces
- User namespaces
- YAML configuration files
- Custom environment variables

TODOs
---------
- Custom bind mounts ([bindfs](http://bindfs.org/) to change permissions or ownership?)
- PTY support for shells inside containers
- More customizable
- Support for starting init (systemd?) inside containers
- Automatic Xauth