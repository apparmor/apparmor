# This file is read by image-garden when spread is allocating test machines.
# All the package installation happens through cloud-init profiles defined
# below.

# NOTE: Should the kernel be out of date, just increment this value. Make will
# re-create the image whenever the .image-garden.mk file is more recent than
# the image itself. In reality all you need is touch(1), but this is more apt.
unused=1

# This is the cloud-init user-data profile for all Debian systems. Note that it
# is an extension of the default profile necessary for operation of
# image-garden.
define DEBIAN_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
packages:
- apache2-dev
- attr
- autoconf
- autoconf-archive
- automake
- bison
- build-essential
- dejagnu
- dosfstools
- flake8
- flex
- fuse-overlayfs
- gdb
- gettext
- libdbus-1-dev
- libpam0g-dev
- libtool
- liburing-dev
- libzstd-dev
- pkg-config
- proftpd-core
- python3-all-dev
- python3-gi
- python3-notify2
- python3-psutil
- python3-setuptools
- python3-tk
- python3-ttkthemes
- socat
- swig
- tinyproxy
# Update all the packages. This allows us to be on the up-to-date kernel
# version that we cannot otherwise easily select with cloud init alone.  Note
# that we do not need to reboot the system as image garden shuts down the image
# after first boot. On subsequent boot we will be running the latest kernel.
package_upgrade: true
package_update: true
endef

# Ubuntu shares cloud-init profile with Debian.
UBUNTU_CLOUD_INIT_USER_DATA_TEMPLATE=$(DEBIAN_CLOUD_INIT_USER_DATA_TEMPLATE)

# This is the cloud-init user-data profile for openSUSE Tumbleweed.
define OPENSUSE_tumbleweed_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- sed -i -e 's/security=selinux/security=apparmor/g' /etc/default/grub
- update-bootloader
packages:
- apache2-devel
- attr
- autoconf
- autoconf-archive
- automake
- bison
- dbus-1-devel
- dejagnu
- dosfstools
- flex
- fuse-overlayfs
- gcc
- gcc-c++
- gdb
- gettext
- gobject-introspection
- libtool
- liburing2-devel
- libzstd-devel
- make
- pam-devel
- pkg-config
- python3-devel
- python3-flake8
- python3-notify2
- python3-psutil
- python3-setuptools
- python3-setuptools
- python3-tk
- python311
- python311-devel
- socat
- swig
- which
# See above for rationale.
package_upgrade: true
package_update: true
endef

define FEDORA_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
packages:
- attr
- autoconf
- autoconf-archive
- automake
- bison
- dbus-devel
- dejagnu
- dosfstools
- flex
- gdb
- gettext
- httpd-devel
- libstdc++-static
- libtool
- liburing-devel
- libzstd-devel
- pam-devel
- perl
- pkg-config
- python3-devel
- python3-flake8
- python3-gobject-base
- python3-notify2
- python3-tkinter
- socat
- swig
# See above for rationale.
package_upgrade: true
package_update: true
endef
