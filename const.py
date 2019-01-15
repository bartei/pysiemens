MaxVars = 20


# Block type
Block_OB = 0x38
Block_DB = 0x41
Block_SDB = 0x42
Block_FC = 0x43
Block_SFC = 0x44
Block_FB = 0x45
Block_SFB = 0x46

# Sub Block Type
SubBlk_OB  = 0x08
SubBlk_DB  = 0x0A
SubBlk_SDB = 0x0B
SubBlk_FC  = 0x0C
SubBlk_SFC = 0x0D
SubBlk_FB  = 0x0E
SubBlk_SFB = 0x0F

# Block languages
BlockLangAWL = 0x01
BlockLangKOP = 0x02
BlockLangFUP = 0x03
BlockLangSCL = 0x04
BlockLangDB = 0x05
BlockLangGRAPH = 0x06

# PLC Status
S7PlcStatuses = [
    {
        'Code': 0x00,
        'Description': 'Cpu Status Unknown'
    },
    {
        'Code': 0x04,
        'Description': 'Cpu In Stop'
    },
    {
        'Code': 0x08,
        'Description': 'Cpu In Run'
    },
]


# S7 Error Codes
Code7Ok = 0x0000
Code7AddressOutOfRange = 0x0005
Code7InvalidTransportSize = 0x0006
Code7WriteDataSizeMismatch = 0x0007
Code7ResItemNotAvailable = 0x000A
Code7ResItemNotAvailable1 = 0xD209
Code7InvalidValue = 0xDC01
Code7NeedPassword = 0xD241
Code7InvalidPassword = 0xD602
Code7NoPasswordToClear = 0xD604
Code7NoPasswordToSet = 0xD605
Code7FunNotAvailable = 0x8104
Code7DataOverPDU = 0x8500

# Result transport size
TS_ResBit = 0x03
TS_ResByte = 0x04
TS_ResInt = 0x05
TS_ResReal = 0x07
TS_ResOctet = 0x09

# Control codes
CodeControlUnknown = 0
CodeControlColdStart = 1# Cold start
CodeControlWarmStart = 2# Warm start
CodeControlStop = 3     # Stop
CodeControlCompress = 4 # Compress
CodeControlCpyRamRom = 5# Copy Ram to Rom
CodeControlInsDel = 6   # Insert in working ram the block downloaded

# PDU Type
PduType_request = 1     # family request
PduType_response = 3    # family response
PduType_userdata = 7    # family user data

