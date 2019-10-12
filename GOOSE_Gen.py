from pyasn1.codec.ber import encoder
from pyasn1.type import tag
from scapy.arch import show_interfaces
from scapy.layers.l2 import Ether
from scapy.layers.l2 import Dot1Q
from scapy.sendrecv import sendp
from scapy.utils import hexdump

from goose import GOOSE
from goose_pdu import AllData
from goose_pdu import Data
from goose_pdu import IECGoosePDU

#Declare variables for packets
v0 = "BIED100PROT/LLN0$Alarm"
v1 = 2000
v2 = 'BIED100PROT/LLN0$Alarm'
v3 = 'BIED100PROT/LLN0$Alarm'
v4 = b"\x5c\xd3\xd9\xac\x91\x68\x72\x0a"
v5 = 1
v6 = 0
v7 = False
v8= 1
v9 = False
v10 = 3


if __name__ == '__main__':
    g = IECGoosePDU().subtype(
        implicitTag=tag.Tag(
            tag.tagClassApplication,
            tag.tagFormatConstructed,
            1
        )
    )

    g.setComponentByName('gocbRef', v0) #v0
    g.setComponentByName('timeAllowedtoLive', v1) #v1
    g.setComponentByName('datSet', v2) #v2
    g.setComponentByName('goID', v3) #v3
    g.setComponentByName('t', v4) #v4
    g.setComponentByName('stNum', v5) #v5
    g.setComponentByName('sqNum', v6) #v6
    g.setComponentByName('test', v7) #v7
    g.setComponentByName('confRev', v8) #v8
    g.setComponentByName('ndsCom', v9) #v9
    g.setComponentByName('numDatSetEntries', v10) #v10

    #************V11************
    d = AllData().subtype(
        implicitTag=tag.Tag(
            tag.tagClassContext,
            tag.tagFormatConstructed,
            11
        )
    )

    d1 = Data()
    d1.setComponentByName('boolean', False)
    d2 = Data()
    d2.setComponentByName('boolean', False)
    d3 = Data()
    d3.setComponentByName('boolean', False)
    d.setComponentByPosition(0, d1)
    d.setComponentByPosition(1, d2)
    d.setComponentByPosition(2, d3)
    g.setComponentByName('allData', d)
    # ************V11************
    hexdump(
        Ether(src='00:09:8e:21:73:25', dst="01:0c:cd:01:00:01") /
        Dot1Q(vlan=0x00, type=0x88b8, prio=0) /
        GOOSE(APPID=int(0x000003e8), Length=125) /
        encoder.encode(g)
    )
'''
0000  01 0C CD 01 00 01 00 09 8E 21 73 25 81 00 00 00  .........!s%....
0010  88 B8 03 E8 00 7D 00 00 00 00 61 73 80 16 42 49  .....}....as..BI
0020  45 44 31 30 30 50 52 4F 54 2F 4C 4C 4E 30 24 41  ED100PROT/LLN0$A
0030  6C 61 72 6D 81 02 07 D0 82 16 42 49 45 44 31 30  larm......BIED10
0040  30 50 52 4F 54 2F 4C 4C 4E 30 24 41 6C 61 72 6D  0PROT/LLN0$Alarm
0050  83 16 42 49 45 44 31 30 30 50 52 4F 54 2F 4C 4C  ..BIED100PROT/LL
0060  4E 30 24 41 6C 61 72 6D 84 08 5C D3 D9 AC 91 68  N0$Alarm..\....h
0070  72 0A 85 01 01 86 01 00 87 01 00 88 01 01 89 01  r...............
0080  00 8A 01 03 AB 09 83 01 00 83 01 00 83 01 00     ...............
'''