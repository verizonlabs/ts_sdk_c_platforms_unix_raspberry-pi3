## Overview

https://github.com/ggary9424/miniFirewall.git

The package is a mini-firewall which is rebuilt according [this artical](http://www.roman10.net/2011/07/23/a-linux-firewall-using-netfilter-part-1overview/) 

#### Environment
Linux kernel for version 4.4.0 .



#### Build and Install

Install mini firewall
```bash
make
sudo insmod mf_km.ko
```

Uninstall the mini firewall
```bash
sudo rmmod mf_km
```
