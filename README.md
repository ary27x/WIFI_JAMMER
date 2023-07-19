# 802.11 Wifi Jammer
**Infinitely disconnects clients one by one from a 802.11 network**

Prerequisites
-------------

* Wireless adapter supporting monitor mode and packet injection
* Python with ***scapy*** and ***colorama*** installed

Usage 
------
``` shell
python jammer.py <interface> <noise_filter_flag>
```
* The interface mentioned should have monitor mode already ON.
* The noise_filter_flag could be either 1 (True : noise filter is on) or 0 (False: noise filter is off)
  
Example:
``` shell
python jammer.py wlan0mon 1
```

