import const

ISO_CR = bytearray()
ISO_CR.append(0x03)  # RFC 1006 ID (3)
ISO_CR.append(0x00)  # Reserved, always 0
ISO_CR.append(0x00)  # High part of packet length (entire frame, payload and TPDU included)
ISO_CR.append(0x16)  # Low part of packet length (entire frame, payload and TPDU included)
# COTP (ISO 8073 Header)
ISO_CR.append(0x11)  # PDU Size Length
ISO_CR.append(0xE0)  # CR - Connection Request ID
ISO_CR.append(0x00)  # Dst Reference HI
ISO_CR.append(0x00)  # Dst Reference LO
ISO_CR.append(0x00)  # Src Reference HI
ISO_CR.append(0x00)  # Src Reference LO
ISO_CR.append(0x00)  # Class + Options Flags
ISO_CR.append(0xC0)  # PDU Max Length ID
ISO_CR.append(0x01)  # PDU Max Length HI
ISO_CR.append(0x0A)  # PDU Max Length LO
ISO_CR.append(0xC1)  # Src TSAP Identifier
ISO_CR.append(0x02)  # Src TSAP Length (2 bytes)
ISO_CR.append(0x01)  # Src TSAP HI (will be overwritten)
ISO_CR.append(0x00)  # Src TSAP LO (will be overwritten)
ISO_CR.append(0xC2)  # Dst TSAP Identifier
ISO_CR.append(0x02)  # Dst TSAP Length (2 bytes)
ISO_CR.append(0x01)  # Dst TSAP HI (will be overwritten)
ISO_CR.append(0x02)  # Dst TSAP LO (will be overwritten)

TPKT_ISO = bytearray()
TPKT_ISO.append(0x03)
TPKT_ISO.append(0x00)
TPKT_ISO.append(0x00)
TPKT_ISO.append(0x1f)  # Telegram Length (Data Size + 31 or 35)
TPKT_ISO.append(0x02)  # COTP See Above For Info
TPKT_ISO.append(0xf0)
TPKT_ISO.append(0x80)

S7_PN = bytearray()
S7_PN.append(0x03)
S7_PN.append(0x00)
S7_PN.append(0x00)
S7_PN.append(0x19)

S7_PN.append(0x02)
S7_PN.append(0xf0)
S7_PN.append(0x80)  # TPKT + COTP (see above for info)

S7_PN.append(0x32)
S7_PN.append(0x01)
S7_PN.append(0x00)
S7_PN.append(0x00)

S7_PN.append(0x04)
S7_PN.append(0x00)
S7_PN.append(0x00)
S7_PN.append(0x08)

S7_PN.append(0x00)
S7_PN.append(0x00)
S7_PN.append(0xf0)
S7_PN.append(0x00)

S7_PN.append(0x00)
S7_PN.append(0x01)
S7_PN.append(0x00)
S7_PN.append(0x01)


S7_PN.append(0x00)
S7_PN.append(0x1e)  # PDU Length Requested = HI-LO Here Default 480 bytes


S7_RW = bytearray()
S7_RW.append(0x03)
S7_RW.append(0x00)

S7_RW.append(0x00)
S7_RW.append(0x1f)  # Telegram Length (Data Size + 31 or 35)

S7_RW.append(0x02)
S7_RW.append(0xf0)
S7_RW.append(0x80)  # COTP (see above for info)

S7_RW.append(0x32)  # S7 Protocol ID

S7_RW.append(0x01)  # Job Type

S7_RW.append(0x00)
S7_RW.append(0x00)  # Redundancy identification

S7_RW.append(0x05)
S7_RW.append(0x00)  # PDU Reference

S7_RW.append(0x00)
S7_RW.append(0x0e)  # Parameters Length

S7_RW.append(0x00)
S7_RW.append(0x00)  # Data Length = Size(bytes) + 4

S7_RW.append(0x04)  # Function 4 Read Var, 5 Write Var

S7_RW.append(0x01)  # Items count

S7_RW.append(0x12)  # Var spec.

S7_RW.append(0x0a)  # Length of remaining bytes

S7_RW.append(0x10)  # Syntax ID

S7_RW.append(const.S7WLByte)  # Transport Size idx=22

S7_RW.append(0x00)
S7_RW.append(0x00)  # Num Elements

S7_RW.append(0x00)
S7_RW.append(0x00)  # DB Number

S7_RW.append(0x84)  # Area Type

S7_RW.append(0x00)
S7_RW.append(0x00)
S7_RW.append(0x00)  # Area Offset
# WR Area
S7_RW.append(0x00)  # Reserved

S7_RW.append(0x04)  # Transport Size

S7_RW.append(0x00)  #
S7_RW.append(0x00)  # Data Length * 8 (if not bit or timer or counter)

Size_RD = 31
Size_WR = 35

S7_MRD_HEADER = bytearray()
S7_MRD_HEADER.append(0x03)
S7_MRD_HEADER.append(0x00)
S7_MRD_HEADER.append(0x00)
S7_MRD_HEADER.append(0x1f)  # Telegram Length

S7_MRD_HEADER.append(0x02)
S7_MRD_HEADER.append(0xf0)
S7_MRD_HEADER.append(0x80)  # COTP

S7_MRD_HEADER.append(0x32)  # S7 Protocol ID

S7_MRD_HEADER.append(0x01)  # Job Type

S7_MRD_HEADER.append(0x00)
S7_MRD_HEADER.append(0x00)  # Redundancy identification

S7_MRD_HEADER.append(0x05)
S7_MRD_HEADER.append(0x00)  # PDU Reference

S7_MRD_HEADER.append(0x00)
S7_MRD_HEADER.append(0x0e)  # Parameters Length

S7_MRD_HEADER.append(0x00)
S7_MRD_HEADER.append(0x00)  # Data Length = Size(bytes) + 4

S7_MRD_HEADER.append(0x04)  # Function 4 Read Var, 5 Write Var

S7_MRD_HEADER.append(0x01)  # Items count (idx 18)

S7_MRD_ITEM = bytearray()
S7_MRD_ITEM.append(0x12)  # Var Spec

S7_MRD_ITEM.append(0x0a)  # Length of remaining bytes

S7_MRD_ITEM.append(0x10)  # Syntax ID

S7_MRD_ITEM.append(const.S7WLByte)  # Transport Size idx = 3

S7_MRD_ITEM.append(0x00)  #
S7_MRD_ITEM.append(0x00)  # Num Elements

S7_MRD_ITEM.append(0x00)  #
S7_MRD_ITEM.append(0x00)  # DB Number or 0

S7_MRD_ITEM.append(0x84)  # Area Type

S7_MRD_ITEM.append(0x00)  #
S7_MRD_ITEM.append(0x00)  #
S7_MRD_ITEM.append(0x00)  # Area Offset

S7_MWR_HEADER = bytearray()
S7_MWR_HEADER.append(0x03)
S7_MWR_HEADER.append(0x00)
S7_MWR_HEADER.append(0x00)
S7_MWR_HEADER.append(0x14)  # Telegram Length

S7_MWR_HEADER.append(0x02)
S7_MWR_HEADER.append(0xf0)
S7_MWR_HEADER.append(0x80)  # COTP

S7_MWR_HEADER.append(0x32)  # S7 Protocol ID

S7_MWR_HEADER.append(0x01)  # Job Type

S7_MWR_HEADER.append(0x00)  #
S7_MWR_HEADER.append(0x00)  # Redundancy identification

S7_MWR_HEADER.append(0x05)  #
S7_MWR_HEADER.append(0x00)  # PDU Reference

S7_MWR_HEADER.append(0x00)  #
S7_MWR_HEADER.append(0x0e)  # Parameters Length (idx 13)

S7_MWR_HEADER.append(0x00)  #
S7_MWR_HEADER.append(0x00)  # Data Length = Size(bytes) + 4 (idx 15)

S7_MWR_HEADER.append(0x05)  # Function 5 Write Var

S7_MWR_HEADER.append(0x01)  # Items count (idx 18)

S7_MWR_PARAM = bytearray()
S7_MWR_PARAM.append(0x12)  # Var Spec.

S7_MWR_PARAM.append(0x0a)  # Length of remaining bytes

S7_MWR_PARAM.append(0x10)  # Syntax ID

S7_MWR_PARAM.append(const.S7WLByte)  # Transport Size idx=3

S7_MWR_PARAM.append(0x00)  #
S7_MWR_PARAM.append(0x00)  # Num Elements

S7_MWR_PARAM.append(0x00)  #
S7_MWR_PARAM.append(0x00)  # DB Number (if any, else 0)

S7_MWR_PARAM.append(0x84)  # Area Type

S7_MWR_PARAM.append(0x00)  #
S7_MWR_PARAM.append(0x00)  #
S7_MWR_PARAM.append(0x00)  # Area Offset

S7_SZL_FIRST = bytearray()

S7_SZL_FIRST.append(0x03)
S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0x21)

S7_SZL_FIRST.append(0x02)
S7_SZL_FIRST.append(0xf0)
S7_SZL_FIRST.append(0x80)
S7_SZL_FIRST.append(0x32)

S7_SZL_FIRST.append(0x07)
S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0x00)

S7_SZL_FIRST.append(0x05)
S7_SZL_FIRST.append(0x00)  # Sequence out

S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0x08)
S7_SZL_FIRST.append(0x00)

S7_SZL_FIRST.append(0x08)
S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0x01)
S7_SZL_FIRST.append(0x12)

S7_SZL_FIRST.append(0x04)
S7_SZL_FIRST.append(0x11)
S7_SZL_FIRST.append(0x44)
S7_SZL_FIRST.append(0x01)

S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0xff)
S7_SZL_FIRST.append(0x09)
S7_SZL_FIRST.append(0x00)

S7_SZL_FIRST.append(0x04)

S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0x00)  # ID (29)

S7_SZL_FIRST.append(0x00)
S7_SZL_FIRST.append(0x00)  # Index (31)

S7_SZL_NEXT = bytearray()
S7_SZL_NEXT.append(0x03)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x21)

S7_SZL_NEXT.append(0x02)
S7_SZL_NEXT.append(0xf0)
S7_SZL_NEXT.append(0x80)
S7_SZL_NEXT.append(0x32)

S7_SZL_NEXT.append(0x07)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x06)

S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x0c)
S7_SZL_NEXT.append(0x00)

S7_SZL_NEXT.append(0x04)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x01)
S7_SZL_NEXT.append(0x12)

S7_SZL_NEXT.append(0x08)
S7_SZL_NEXT.append(0x12)
S7_SZL_NEXT.append(0x44)
S7_SZL_NEXT.append(0x01)

S7_SZL_NEXT.append(0x01)  # Sequence

S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)

S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)
S7_SZL_NEXT.append(0x00)


# Get Date/Time request
S7_GET_DT = bytearray()
S7_GET_DT.append(0x03)
S7_GET_DT.append(0x00)
S7_GET_DT.append(0x00)
S7_GET_DT.append(0x1d)

S7_GET_DT.append(0x02)
S7_GET_DT.append(0xf0)
S7_GET_DT.append(0x80)
S7_GET_DT.append(0x32)

S7_GET_DT.append(0x07)
S7_GET_DT.append(0x00)
S7_GET_DT.append(0x00)
S7_GET_DT.append(0x38)

S7_GET_DT.append(0x00)
S7_GET_DT.append(0x00)
S7_GET_DT.append(0x08)
S7_GET_DT.append(0x00)

S7_GET_DT.append(0x04)
S7_GET_DT.append(0x00)
S7_GET_DT.append(0x01)
S7_GET_DT.append(0x12)

S7_GET_DT.append(0x04)
S7_GET_DT.append(0x11)
S7_GET_DT.append(0x47)
S7_GET_DT.append(0x01)

S7_GET_DT.append(0x00)
S7_GET_DT.append(0x0a)
S7_GET_DT.append(0x00)
S7_GET_DT.append(0x00)

S7_GET_DT.append(0x00)

# Set Date/Time command
S7_SET_DT = bytearray()
S7_SET_DT.append(0x03)
S7_SET_DT.append(0x00)
S7_SET_DT.append(0x00)
S7_SET_DT.append(0x27)

S7_SET_DT.append(0x02)
S7_SET_DT.append(0xf0)
S7_SET_DT.append(0x80)
S7_SET_DT.append(0x32)

S7_SET_DT.append(0x07)
S7_SET_DT.append(0x00)
S7_SET_DT.append(0x00)
S7_SET_DT.append(0x89)

S7_SET_DT.append(0x03)
S7_SET_DT.append(0x00)
S7_SET_DT.append(0x08)
S7_SET_DT.append(0x00)

S7_SET_DT.append(0x0e)
S7_SET_DT.append(0x00)
S7_SET_DT.append(0x01)
S7_SET_DT.append(0x12)

S7_SET_DT.append(0x04)
S7_SET_DT.append(0x11)
S7_SET_DT.append(0x47)
S7_SET_DT.append(0x02)

S7_SET_DT.append(0x00)
S7_SET_DT.append(0xff)
S7_SET_DT.append(0x09)
S7_SET_DT.append(0x00)

S7_SET_DT.append(0x0a)
S7_SET_DT.append(0x00)

S7_SET_DT.append(0x19)  # Hi part of Year (idx=30)
S7_SET_DT.append(0x13)  # Lo part of Year
S7_SET_DT.append(0x12)  # Month
S7_SET_DT.append(0x06)  # Day
S7_SET_DT.append(0x17)  # Hour
S7_SET_DT.append(0x37)  # Min
S7_SET_DT.append(0x13)  # Sec
S7_SET_DT.append(0x00)  # ms
S7_SET_DT.append(0x01)  # Day Of Week

# S7 Set Session Password
S7_SET_PWD = bytearray()
S7_SET_PWD.append(0x03)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x25)

S7_SET_PWD.append(0x02)
S7_SET_PWD.append(0xf0)
S7_SET_PWD.append(0x80)
S7_SET_PWD.append(0x32)

S7_SET_PWD.append(0x07)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x27)

S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x08)
S7_SET_PWD.append(0x00)

S7_SET_PWD.append(0x0c)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x01)
S7_SET_PWD.append(0x12)

S7_SET_PWD.append(0x04)
S7_SET_PWD.append(0x11)
S7_SET_PWD.append(0x45)
S7_SET_PWD.append(0x01)

S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0xff)
S7_SET_PWD.append(0x09)
S7_SET_PWD.append(0x00)

S7_SET_PWD.append(0x08)

# 8 Char Encoded Password
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)
S7_SET_PWD.append(0x00)


# S7 Clear Session Password
S7_CLR_PWD = bytearray()
S7_CLR_PWD.append(0x03)
S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x1d)

S7_CLR_PWD.append(0x02)
S7_CLR_PWD.append(0xf0)
S7_CLR_PWD.append(0x80)
S7_CLR_PWD.append(0x32)

S7_CLR_PWD.append(0x07)
S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x29)

S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x08)
S7_CLR_PWD.append(0x00)

S7_CLR_PWD.append(0x04)
S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x01)
S7_CLR_PWD.append(0x12)

S7_CLR_PWD.append(0x04)
S7_CLR_PWD.append(0x11)
S7_CLR_PWD.append(0x45)
S7_CLR_PWD.append(0x02)

S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x0a)
S7_CLR_PWD.append(0x00)
S7_CLR_PWD.append(0x00)

S7_CLR_PWD.append(0x00)


# S7 STOP request
S7_STOP = bytearray()
S7_STOP.append(0x03)
S7_STOP.append(0x00)
S7_STOP.append(0x00)
S7_STOP.append(0x21)

S7_STOP.append(0x02)
S7_STOP.append(0xf0)
S7_STOP.append(0x80)
S7_STOP.append(0x32)

S7_STOP.append(0x01)
S7_STOP.append(0x00)
S7_STOP.append(0x00)
S7_STOP.append(0x0e)

S7_STOP.append(0x00)
S7_STOP.append(0x00)
S7_STOP.append(0x10)
S7_STOP.append(0x00)

S7_STOP.append(0x00)
S7_STOP.append(0x29)
S7_STOP.append(0x00)
S7_STOP.append(0x00)

S7_STOP.append(0x00)
S7_STOP.append(0x00)
S7_STOP.append(0x00)
S7_STOP.append(0x09)

S7_STOP.append(0x50)
S7_STOP.append(0x5f)
S7_STOP.append(0x50)
S7_STOP.append(0x52)

S7_STOP.append(0x4f)
S7_STOP.append(0x47)
S7_STOP.append(0x52)
S7_STOP.append(0x41)

S7_STOP.append(0x4d)

# S7 HOT Start request
S7_HOT_START = bytearray()
S7_HOT_START.append(0x03)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x25)

S7_HOT_START.append(0x02)
S7_HOT_START.append(0xf0)
S7_HOT_START.append(0x80)
S7_HOT_START.append(0x32)

S7_HOT_START.append(0x01)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x0c)

S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x14)
S7_HOT_START.append(0x00)

S7_HOT_START.append(0x00)
S7_HOT_START.append(0x28)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)

S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)

S7_HOT_START.append(0xfd)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x00)
S7_HOT_START.append(0x09)

S7_HOT_START.append(0x50)
S7_HOT_START.append(0x5f)
S7_HOT_START.append(0x50)
S7_HOT_START.append(0x52)

S7_HOT_START.append(0x4f)
S7_HOT_START.append(0x47)
S7_HOT_START.append(0x52)
S7_HOT_START.append(0x41)

S7_HOT_START.append(0x4d)

# S7 COLD Start request
S7_COLD_START = bytearray()
S7_COLD_START.append(0x03)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x27)

S7_COLD_START.append(0x02)
S7_COLD_START.append(0xf0)
S7_COLD_START.append(0x80)
S7_COLD_START.append(0x32)

S7_COLD_START.append(0x01)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x0f)

S7_COLD_START.append(0x00)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x16)
S7_COLD_START.append(0x00)

S7_COLD_START.append(0x00)
S7_COLD_START.append(0x28)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x00)

S7_COLD_START.append(0x00)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x00)

S7_COLD_START.append(0xfd)
S7_COLD_START.append(0x00)
S7_COLD_START.append(0x02)
S7_COLD_START.append(0x43)

S7_COLD_START.append(0x20)
S7_COLD_START.append(0x09)
S7_COLD_START.append(0x50)
S7_COLD_START.append(0x5f)

S7_COLD_START.append(0x50)
S7_COLD_START.append(0x52)
S7_COLD_START.append(0x4f)
S7_COLD_START.append(0x47)

S7_COLD_START.append(0x52)
S7_COLD_START.append(0x41)
S7_COLD_START.append(0x4d)

pduStart = 0x28  # CPU start
pduStop = 0x29  # CPU stop
pduAlreadyStarted = 0x02  # CPU already in run mode
pduAlreadyStopped = 0x07  # CPU already in stop mode

# S7 Get PLC Status
S7_GET_STAT = bytearray()
S7_GET_STAT.append(0x03)
S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0x21)

S7_GET_STAT.append(0x02)
S7_GET_STAT.append(0xf0)
S7_GET_STAT.append(0x80)
S7_GET_STAT.append(0x32)

S7_GET_STAT.append(0x07)
S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0x2c)

S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0x08)
S7_GET_STAT.append(0x00)

S7_GET_STAT.append(0x08)
S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0x01)
S7_GET_STAT.append(0x12)

S7_GET_STAT.append(0x04)
S7_GET_STAT.append(0x11)
S7_GET_STAT.append(0x44)
S7_GET_STAT.append(0x01)

S7_GET_STAT.append(0x00)
S7_GET_STAT.append(0xff)
S7_GET_STAT.append(0x09)
S7_GET_STAT.append(0x00)

S7_GET_STAT.append(0x04)
S7_GET_STAT.append(0x04)
S7_GET_STAT.append(0x24)
S7_GET_STAT.append(0x00)

S7_GET_STAT.append(0x00)


# S7 Get Block Info Request Header (contains also ISO Header and COTP Header)
S7_BI = bytearray()
S7_BI.append(0x03)
S7_BI.append(0x00)
S7_BI.append(0x00)
S7_BI.append(0x25)

S7_BI.append(0x02)
S7_BI.append(0xf0)
S7_BI.append(0x80)
S7_BI.append(0x32)

S7_BI.append(0x07)
S7_BI.append(0x00)
S7_BI.append(0x00)
S7_BI.append(0x05)

S7_BI.append(0x00)
S7_BI.append(0x00)
S7_BI.append(0x08)
S7_BI.append(0x00)

S7_BI.append(0x0c)
S7_BI.append(0x00)
S7_BI.append(0x01)
S7_BI.append(0x12)

S7_BI.append(0x04)
S7_BI.append(0x11)
S7_BI.append(0x43)
S7_BI.append(0x03)

S7_BI.append(0x00)
S7_BI.append(0xff)
S7_BI.append(0x09)
S7_BI.append(0x00)

S7_BI.append(0x08)
S7_BI.append(0x30)

S7_BI.append(0x41)  # Block Type

S7_BI.append(0x30)  #
S7_BI.append(0x30)  #
S7_BI.append(0x30)  #
S7_BI.append(0x30)  #
S7_BI.append(0x30)  # ASCII Block Number

S7_BI.append(0x41)