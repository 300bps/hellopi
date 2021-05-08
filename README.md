## Hello Pi ##
_Hello Pi_ is a program that identifies the ip address of Raspberry Pis added to the local area network.

### What It Does: ###
_Hello Pi_ makes it easy to identify the ip address of a Raspberry Pi (RPi) computer added to the same DHCP-configured 
local area network (LAN). Additionally, it can report the ip address of other devices added to the same LAN. It 
eliminates the need to attach a display and keyboard to the RPi solely to discover its ip address.
  
### The Problem It Solves: ###
A frequent, common problem when commissioning a new RPi is that the ip address that it will be assigned is not 
initially known. Traditionally, this has meant that the user must connect a display and keyboard to the new RPi in 
order to check what ip address it has been assigned. This is inconvenient and can be a problem if the RPi is intended 
to be used in a "headless" (no connected display) configuration. A headless setup would typically be configured using 
SSH to login remotely from another computer, but this requires knowledge of the ip address of the target RPi. _Hello Pi_ 
makes it easy to learn the ip address of a device when it is powered-up while connected to the same LAN.

### How To Use It: ###
_Hello Pi_ is run from a computer (the 'Host') connected to the same DHCP-configured LAN as the RPi (the 'Target') or 
other device to be discovered. 

1. Using the command-prompt, start _Hello Pi_ on the Host.
   * Note that the -h option can be used to see a list of available command options.
2. The initial state of the Target (RPi or device) is powered-down/unpowered.
3. Connect Target to the LAN.
   * If using Ethernet, physically connect the cable.
   * If using WiFi, configure the _wpa_supplicant.conf_ file in the boot folder of the OS image.
4. Power-up the Target and wait while it boots.
5. Observe the output of _Hello Pi_ on the Host to learn the ip address assigned to the Target.
6. To repeat the process, power-down the Target and return to step 2. 

### Theory of Operation: ###
This section is presented for those curious about how the program works, but is not required reading  
to use the program.  

_Hello Pi_ listens to the exchange between the Target device and the DHCP server. When the Target is 
powered-up while connected to the LAN, it sends a broadcast DHCP Discovery message. The DHCP server receives
this message and sends a DHCP Offer response. The Target then replies with a broadcast DHCP Request response 
acknowledging acceptance of the ip address that was offered.

Since the Target's DHCP Request message is broadcast to all devices on the LAN, _Hello Pi_ on the Host listens
for this message and reports the accepted ip address.

_Hello Pi_ has the option to report the ip address of only RPis, or can be instructed to report the ip 
address of any device that connects and is configured via DHCP. In order to discriminate between RPis and
other devices, the OUI (Organizationally Unique Identifier) of the MAC address is compared to the
OUIs registered to the Raspberry Pi Foundation.  


### Platform-specific Details: ###
##### Linux/BSD: #####
_Hello Pi_ on Linux must be run with elevated privileges (via sudo or as root). This is required to allow it to create a
"raw socket", which it uses to see DHCP Request broadcast messages sent by devices connecting to the LAN. From these
messages, it can display the ip address of the connecting RPi or device. 

##### Windows: #####
_Hello Pi_ on Windows must be run with administrator privileges. This is required to allow it to create a
"raw socket", which it uses to see DHCP Request broadcast messages sent by devices connecting to the LAN. From these
messages, it can display the ip address of the connecting RPi or device.

TODO: ADD NOTE ABOUT FIREWALL REQUIREMENTS TO ALLOW READING OF BROADCAST DHCP
