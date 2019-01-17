import const
import struct
import datetime
import utils

bias = 621355968000000000 # "decimicros" between 0001-01-01 00:00:00 and 1970-01-01 00:00:00

class Area(object):
    PE = 0x81
    PA = 0x82
    MK = 0x83
    DB = 0x84
    CT = 0x1C
    TM = 0x1D

class DataTypes(object):
    Bit = 0x01
    Byte = 0x02
    Char = 0x03
    Word = 0x04
    Int = 0x05
    DWord = 0x06
    DInt = 0x07
    Real = 0x08
    Counter = 0x1C
    Timer = 0x1D

class TransportSizes(object):
    Bit = 0x03
    Byte = 0x04
    Int = 0x05
    Real = 0x07
    Octet = 0x09

def BCDtoByte(B):
    return ((B >> 4) * 10) + (B & 0x0F)

def ByteToBCD(Value):
    return ((Value // 10) << 4) | (Value % 10)

def CopyFrom(Buffer, Pos, Size):
    return Buffer[Pos:Pos+Size]


def data_size(data_type):
    if data_type ==  DataTypes.Bit:
        return 1
    elif data_type == DataTypes.Byte:
        return 1
    elif data_type == DataTypes.Char:
        return 1
    elif data_type == DataTypes.Word:
        return 2
    elif data_type == DataTypes.DWord:
        return 4
    elif data_type == DataTypes.Int:
        return 2
    elif data_type == DataTypes.DInt:
        return 4
    elif data_type == DataTypes.Real:
        return 4
    elif data_type == DataTypes.Counter:
        return 2
    elif data_type == DataTypes.Timer:
        return 2
    else:
        return 0

# Transport Size
def transport_size(data_type):
    if data_type is DataTypes.Bit:
        return TransportSizes.Bit
    elif data_type in [DataTypes.Counter, DataTypes.Timer]:
        return TransportSizes.Octet
    else:
        return TransportSizes.Byte

def GetBitAt(Buffer, Pos, Bit):
    Bit = min(Bit, 7)
    Bit = max(Bit, 0)
    Mask = 1 << Bit
    return (Buffer[Pos] & Mask) != 0

def SetBitAt(Buffer, Pos, Bit, Value):
    Bit = min(Bit, 7)
    Bit = max(Bit, 0)
    Mask = 1 << Bit
    if Value:
        Buffer[Pos] = Buffer[Pos] | Mask
    else:
        Buffer[Pos] = Buffer[Pos] & ~Mask

def GetSIntAt(Buffer, Pos):
    return struct.unpack("b", Buffer[Pos:Pos+1])[0]

def SetSintAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+1] = struct.pack("b", Value)

def GetIntAt(Buffer, Pos):
    return struct.unpack(">h", Buffer[Pos:Pos+2])[0]

def SetIntAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+2] = struct.pack(">h", Value)

def GetDIntAt(Buffer, Pos):
    return struct.unpack(">i", Buffer[Pos:Pos+4])[0]

def SetDIntAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+4] = struct.pack(">i", Value)

def GetLIntAt(Buffer, Pos):
    return struct.unpack(">q", Buffer[Pos:Pos+8])[0]

def SetLIntAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+8] = struct.pack(">q", Value)

def GetUSIntAt(Buffer, Pos):
    return struct.unpack("B", Buffer[Pos:Pos+1])[0]

def SetUSIntAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+1] = struct.pack("B", Value)

def GetUIntAt(Buffer, Pos):
    return struct.unpack(">H", Buffer[Pos:Pos+2])[0]

def SetUIntAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+2] = struct.pack(">H", Value)

def GetUDIntAt(Buffer, Pos):
    return struct.unpack(">I", Buffer[Pos:Pos+4])[0]

def SetUDIntAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+4] = struct.pack(">I", Value)

def GetULIntAt(Buffer, Pos):
    return struct.unpack(">Q", Buffer[Pos:Pos + 8])[0]

def SetULIntAt(Buffer, Pos, Value):
    Buffer[Pos:Pos + 8] = struct.pack(">Q", Value)

def GetByteAt(Buffer, Pos):
    return struct.unpack("B", Buffer[Pos:Pos+1])[0]

def SetByteAt(Buffer, Pos, Value):
    Buffer[Pos:Pos+1] = struct.pack("B", Value)

def GetWordAt(Buffer, Pos):
    return struct.unpack(">H", Buffer[Pos:Pos + 2])[0]

def SetWordAt(Buffer, Pos, Value):
    Buffer[Pos:Pos + 2] = struct.pack(">H", Value)

def GetDWordAt(Buffer, Pos):
    return struct.unpack(">I", Buffer[Pos:Pos + 4])[0]

def SetDWordAt(Buffer, Pos, Value):
    Buffer[Pos:Pos + 4] = struct.pack(">I", Value)

def GetLWordAt(Buffer, Pos):
    return struct.unpack(">Q", Buffer[Pos:Pos + 8])[0]

def SetLWordAt(Buffer, Pos, Value):
    Buffer[Pos:Pos + 8] = struct.pack(">Q", Value)

def GetFloatAt(Buffer, Pos):
    return struct.unpack(">f", Buffer[Pos:Pos + 4])[0]

def SetFloatAt(Buffer, Pos, Value):
    Buffer[Pos:Pos + 4] = struct.pack(">f", Value)

def GetLRealAt(Buffer, Pos):
    return struct.unpack(">d", Buffer[Pos:Pos + 8])[0]

def SetLRealAt(Buffer, Pos, Value):
    Buffer[Pos:Pos + 8] = struct.pack(">d", Value)

def GetDateTimeAt(Buffer, Pos):
    Year = BCDtoByte(Buffer[Pos])
    if Year < 90:
        Year += 2000
    else:
        Year += 1900

    Month = BCDtoByte(Buffer[Pos + 1])
    Day = BCDtoByte(Buffer[Pos + 2])
    Hour = BCDtoByte(Buffer[Pos + 3])
    Min = BCDtoByte(Buffer[Pos + 4])
    Sec = BCDtoByte(Buffer[Pos + 5])
    MSec = (BCDtoByte(Buffer[Pos + 6]) * 10) + (BCDtoByte(Buffer[Pos + 7]) / 10)

    try:
        return datetime.datetime(year=Year, month=Month, day=Day, hour=Hour, minute=Min, second=Sec, microsecond=int(MSec*1000))
    except Exception as e:
        utils.log_error(e)

def SetDateTimeAt(Buffer, Pos, DateTime: datetime.datetime):
    Year = DateTime.year
    if Year > 1999:
        Year = Year - 2000

    Buffer[Pos] = ByteToBCD(Year)
    Buffer[Pos+1] = ByteToBCD(DateTime.month)
    Buffer[Pos+2] = ByteToBCD(DateTime.day)
    Buffer[Pos+3] = ByteToBCD(DateTime.hour)
    Buffer[Pos+4] = ByteToBCD(DateTime.minute)
    Buffer[Pos+5] = ByteToBCD(DateTime.second)
    Buffer[Pos+6] = ByteToBCD(DateTime.microsecond / 10000)
    millis = DateTime.microsecond / 1000
    millis = millis % 10
    millis = millis * 10
    Buffer[Pos+7] = ByteToBCD(DateTime.weekday() + millis)

def GetDateAt(Buffer, Pos):
    Date = datetime.date(year=1990, month=1, day=1)
    Date = Date + datetime.timedelta(days=GetIntAt(Buffer, Pos))
    return Date

def SetDateAt(Buffer, Pos, Date : datetime.date):
    delta = Date - datetime.date(year=1990, month=1, day=1)
    SetIntAt(Buffer, Pos, delta.days)

def GetTODAt(Buffer, Pos):
    date_time = datetime.datetime(year=2000, month=1, day=1, hour=0, minute=0, second=0)
    delta = datetime.timedelta(milliseconds=GetDIntAt(Buffer, Pos))
    date_time = date_time + delta
    return date_time.time()

def SetTODAt(Buffer, Pos, Time: datetime.time):
    ref_dt = datetime.datetime(year=2000, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    cur_dt = datetime.datetime(
        year=2000,
        month=1,
        day=1,
        hour=Time.hour,
        minute=Time.minute,
        second=Time.second,
        microsecond=Time.microsecond
    )

    delta = cur_dt - ref_dt

    millis = round(delta.total_seconds() * 1000 + delta.microseconds / 1000)
    SetDIntAt(Buffer, Pos, millis)

def GetStringAt(Buffer: bytearray, Pos):
    length = Buffer[Pos]
    return Buffer[Pos+1:Pos+length+1].decode(encoding="utf-8")

def GetCharsAt(Buffer: bytearray, Pos, Size):
    return Buffer[Pos:Pos+Size].decode(encoding="utf-8").replace("\x00","")

def GetCounter(Value):
    return BCDtoByte(Value & 0xFF) * 100 + BCDtoByte(Value >> 8)

def GetCounterAt(Buffer, Index):
    return GetCounter(GetWordAt(Buffer, Index))

def ToCounter(Value):
    return ByteToBCD(Value // 100) + (ByteToBCD(Value % 100) << 8)

def SetCounterAt(Buffer, Pos, Value):
    SetWordAt(Buffer, Pos, ToCounter(Value))
