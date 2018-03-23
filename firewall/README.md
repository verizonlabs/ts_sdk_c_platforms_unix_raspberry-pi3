## Overview

Based on the source provided by, https://github.com/ggary9424/miniFirewall.git

#### Environment

Prepare your RPi,

```
$ sudo apt update
$ sudo apt upgrade
$ sudo apt install raspberrypi-kernel-headers
$ sudo apt install --reinstall raspberrypi-bootloader raspberrypi-kernel
$ sudo shutdown -r now
```

#### Build and Install

Build and install the mini-firewall,
```
$ make
$ sudo insmod mf_module.ko
```

Uninstall the mini-firewall,
```
$ sudo rmmod mf_module
```
