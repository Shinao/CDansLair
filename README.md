# CDansLair

[![Build Status](https://travis-ci.org/Shinao/CDansLair.svg?branch=master)](https://travis-ci.org/Shinao/CDansLair)

C++ portable packet viewer and manipulator with ARP Poisoning.


### Preview
Changing an image from a website and throttling the network traffic
<p align="center">
 <img width="50%" src="/docs/cdanslair_spoofer.gif"/><img width="50%" src="/docs/cdanslair_target.gif"/>
</p>

### Capacities
- Portable : tried on Ubuntu & Windows 7
- Packet viewer from network interface
- ARP Poisoning
 - Redirect traffic to us
 - Change packet on the fly (text replace)
 - Throttle network traffic
- Import/Export pcap file

### Using it
- Install Qt4+, qtcreator or qmake
- QtCreator > build or `qmake CDansLair.pro`

### Notes
ARP poisoning only works on Linux : Windows doesn't allow to send custom packets.<br>
Remember to ping the targeted machines before using the ARP Poisoning to populate your arp table, it's not gonna scan your network on his own.
