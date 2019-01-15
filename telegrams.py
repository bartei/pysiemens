import struct
import logging
import utils
import const
import S7

log = logging.getLogger(__file__)

class PduTypes(object):
    ConnectionRequest = 0xE0
    ConnectionConfirm = 0xD0
    DisconnectRequest = 0x80
    DisconnectConfirm = 0xC0
    DataTransfer = 0xF0
    EndOfTransmission = 0x80

class PduSizeValues(object):
    Size_128 = 0x07
    Size_256 = 0x08
    Size_512 = 0x09
    Size_1024 = 0x0A
    Size_2048 = 0x0B
    Size_4096 = 0x0C
    Size_8192 = 0x0D

class PduFunctions(object):
    pduResponse = 0x02  # Response (when error)
    pduFuncRead = 0x04  # Read area
    pduFuncWrite = 0x05  # Write area
    pduNegotiate = 0xF0  # Negotiate PDU length
    pduStart = 0x28  # CPU start
    pduStop = 0x29  # CPU stop
    pduStartUpload = 0x1D  # Start Upload
    pduUpload = 0x1E  # Upload
    pduEndUpload = 0x1F  # EndUpload
    pduReqDownload = 0x1A  # Start Download request
    pduDownload = 0x1B  # Download request
    pduDownloadEnded = 0x1C  # Download end request
    pduControl = 0x28  # Control (insert/delete..)


class PduSubFunctions(object):
    SFun_ListAll = 0x01  # List all blocks
    SFun_ListBoT = 0x02  # List Blocks of type
    SFun_BlkInfo = 0x03  # Get Block info
    SFun_ReadSZL = 0x01  # Read SZL
    SFun_ReadClock = 0x01  # Read Clock (Date and Time)
    SFun_SetClock = 0x02  # Set Clock (Date and Time)
    SFun_EnterPwd = 0x01  # Enter password    for this session
    SFun_CancelPwd = 0x02  # Cancel password    for this session
    SFun_Insert = 0x50  # Insert block
    SFun_Delete = 0x42  # Delete block


class ProtocolObject(object):
    def __init__(self):
        pass

    def from_bytes(self, b):
        pass

    def to_bytes(self):
        return bytearray()


class TPKT(ProtocolObject):
    def __init__(self, protocol_payload : ProtocolObject):
        super(TPKT, self).__init__()
        self.version = 3
        self.reserved = 0
        self.length = 0
        self.payload = protocol_payload

    def to_bytes(self):
        self.length = 4 + len(self.payload.to_bytes())
        elements = [
            self.version,
            self.reserved,
            self.length,
        ]
        result = bytearray()
        result.extend(struct.pack(">BBH", *elements))
        result.extend(self.payload.to_bytes())
        return result

    def header_from_bytes(self, b):
        (
        self.version,
        self.reserved,
        self.length,
        ) = struct.unpack(">BBH", b[0:4])

    def payload_from_bytes(self, b):
        self.payload.from_bytes(b)

    def from_bytes(self, b):
        (
        self.version,
        self.reserved,
        self.length,
        ) = struct.unpack(">BBH", b[0:4])
        self.payload.from_bytes(b[4:])


class COTP_Params(object):
    def __init__(self):
        self.PduSizeCode = 0xC0  # Always the same value in our case
        self.PduSizeLen = 0x01   # Always 1 in our cae
        self.PduSizeVal = PduSizeValues.Size_1024 # That's the default found so far
        self.TSAP = bytearray()

    def to_bytes(self):
        elements = [
            self.PduSizeCode,
            self.PduSizeLen,
            self.PduSizeVal,
        ]
        result = bytearray()
        result.extend(struct.pack(">BBB", *elements))
        result.extend(self.TSAP)
        return result


# COTP Header for CONNECTION REQUEST/CONFIRM - DISCONNECT REQUEST/CONFIRM
class COTP_CO(ProtocolObject):
    def __init__(self):
        super(COTP_CO, self).__init__()

        self.HLength = 0x00                         # Header length : initialized to 6 (length without params - 1)
        self.PDUType = PduTypes.ConnectionRequest
        self.DstRef = 0x0000                        # Destination reference : Always 0x0000
        self.SrcRef = 0x0000                        # Source reference : Always 0x0000
        self.CO_R = 0x00                            # If the telegram is used for Connection request/Confirm,
        self.PduSizeCode = 0xC0                     # Always the same value in our case
        self.PduSizeLen = 0x01                      # Always 1 in our cae
        self.PduSizeVal = PduSizeValues.Size_2048   # That's the default found so far
        self.TSAP = bytearray()

    def to_bytes(self):
        self.HLength = 9 + len(self.TSAP)
        elements = (
            self.HLength,
            self.PDUType,
            self.DstRef,
            self.SrcRef,
            self.CO_R,
            self.PduSizeCode,
            self.PduSizeLen,
            self.PduSizeVal,
        )

        result = bytearray()
        result.extend(struct.pack(">BBHHBBBB", *elements))
        result.extend(self.TSAP)
        return result

    def from_bytes(self, b):
        (
            self.HLength,
            self.PDUType,
            self.DstRef,
            self.SrcRef,
            self.CO_R,
            self.PduSizeCode,
            self.PduSizeLen,
            self.PduSizeVal,
        ) = struct.unpack(">BBHHBBBB", b[0:10])
        self.TSAP = b[10:]


# COTP Header for DATA EXCHANGE
class COTP_DT(ProtocolObject):
    def __init__(self, protocol_payload : ProtocolObject):
        super(COTP_DT, self).__init__()
        self.HLength = 3
        self.PDUType = PduTypes.DataTransfer
        self.EotNum = 0x80
        self.payload = protocol_payload

    def to_bytes(self):
        elements = (
            self.HLength,
            self.PDUType,
            self.EotNum,
        )

        result = bytearray()
        result.extend(struct.pack(">BBB", *elements))
        result.extend(self.payload.to_bytes())
        return result

    def from_bytes(self, b):
        (
            self.HLength,
            self.PDUType,
            self.EotNum,
        ) = struct.unpack(">BBB", b[0:3])
        self.payload.from_bytes(b[3:])


class IsoControlPDU(ProtocolObject):
    def __init__(self, ):
        super(IsoControlPDU, self).__init__()
        self.TPKT = TPKT()
        self.COTP = COTP_CO()

    def assign_control_payload(self, tsap_payload):
        self.COTP.Params.TSAP[:] = tsap_payload

    def to_bytes(self):
        self.TPKT.length = len(self.TPKT.to_bytes()) + len(self.COTP.to_bytes())
        result = bytearray()
        result.extend(self.TPKT.to_bytes())
        result.extend(self.COTP.to_bytes())
        return result


class IsoDataPDU(object):
    def __init__(self, **kwargs):
        self.TPKT = TPKT()
        self.COTP = COTP_DT()

        for item in kwargs.keys():
            if item in self.__dict__.keys():
                self.__dict__[item] = kwargs[item]

    def assign_data_payload(self, p):
        self.COTP.payload[:] = p

    def to_bytes(self):
        self.TPKT.length = len(self.TPKT.to_bytes()) + len(self.COTP.to_bytes())
        result = bytearray()
        result.extend(self.TPKT.to_bytes())
        result.extend(self.COTP.to_bytes())
        return result


class S7ReqHeader(ProtocolObject):
    def __init__(self, protocol_payload : ProtocolObject):
        super(S7ReqHeader, self).__init__()
        self.P = 0x32           # Telegram ID, always 0x32
        self.PduType = 1        # Header Type 1 or 7
        self.AB_EX = 0          # AB currently unknown, maybe it can be used for long numbers.
        self.Sequence = 0x0400   # Message ID. This can be used to make sure a received answer
        self.ParLen = 0         # Length of parameters which follow this header
        self.DataLen = 0        # Length of data which follow the parameters
        self.payload = protocol_payload

    def to_bytes(self):
        self.ParLen = len(self.payload.to_bytes())
        elements = (
            self.P,
            self.PduType,
            self.AB_EX,
            self.Sequence,
            self.ParLen,
            self.DataLen,
        )

        result = bytearray()
        result.extend(struct.pack(">BBHHHH", *elements))
        result.extend(self.payload.to_bytes())
        return result

    def from_bytes(self, b):
        (
            self.P,
            self.PduType,
            self.AB_EX,
            self.Sequence,
            self.ParLen,
            self.DataLen,
        ) = struct.unpack(">BBHHHH", b[0:10])
        self.payload.from_bytes(b[10:])


class S7ResponseHeader23(ProtocolObject):
    def __init__(self, protocol_payload : ProtocolObject):
        super(S7ResponseHeader23, self).__init__()
        self.P = 0x32           # Telegram ID, always 0x32
        self.PduType = 0x00     # Header Type 1 or 7
        self.AB_EX = 0x0000     # AB currently unknown, maybe it can be used for long numbers.
        self.Sequence = 0x0400  # Message ID. This can be used to make sure a received answer
        self.ParLen = 0x0000    # Length of parameters which follow this header
        self.DataLen = 0x0000   # Length of data which follow the parameters
        self.Error = 0x0000     # Error Code
        self.payload = protocol_payload

    def to_bytes(self):
        self.ParLen = len(self.payload.to_bytes())
        self.DataLen = 0
        elements = (
            self.P,
            self.PduType,
            self.AB_EX,
            self.Sequence,
            self.ParLen,
            self.DataLen,
            self.Error,
        )

        result = bytearray()
        result.extend(struct.pack(">BBHHHHH", *elements))
        result.extend(self.payload.to_bytes())
        return result

    def from_bytes(self, b):
        (
            self.P,
            self.PduType,
            self.AB_EX,
            self.Sequence,
            self.ParLen,
            self.DataLen,
            self.Error,
        ) = struct.unpack(">BBHHHHH", b[0:12])
        self.payload.from_bytes(b[12:])


class NegotiateParamsStructure(ProtocolObject):
    def __init__(self):
        super(NegotiateParamsStructure, self).__init__()
        self.FunNegotiate = PduFunctions.pduNegotiate
        self.Unknown = 0
        self.ParallelJobs_1 = 0x0001
        self.ParallelJobs_2 = 0x0001
        self.PDULength = 480        # Requested length for the negotiation

    def to_bytes(self):
        elements = (
            self.FunNegotiate,
            self.Unknown,
            self.ParallelJobs_1,
            self.ParallelJobs_2,
            self.PDULength,
        )

        result = bytearray()
        result.extend(struct.pack(">BBHHH", *elements))
        return result

    def from_bytes(self, b):
        try:
            (
                self.FunNegotiate,
                self.Unknown,
                self.ParallelJobs_1,
                self.ParallelJobs_2,
                self.PDULength
            ) = struct.unpack(">BBHHH", b)
        except Exception as e:
            log.error("Unable to unpack given bytearray")
            utils.log_error(e)


class ReadAreaRequest(ProtocolObject):
    def __init__(self,
                 area_type=0x84,
                 area_offset=0,
                 db_number=1,
                 num_elements=1,
                 transport_size=S7.Length.Byte):
        super(ReadAreaRequest, self).__init__()
        self.function = 4 # 4 read, 5 write
        self.items_count = 1
        self.var_spec = 0x12
        self.remaining_bytes_len = 0x0a
        self.syntax_id = 0x10
        self.transport_size = transport_size
        self.num_elements = num_elements
        self.db_number = db_number
        self.area_type = area_type

        no_shift_areas = (
            S7.Length.Bit,
            S7.Length.Counter,
            S7.Length.Timer,
        )
        if area_offset in no_shift_areas:
            self.area_offset = area_offset
        else:
            self.area_offset = (area_offset << 3)

    def to_bytes(self):
        elements = (
            self.function,
            self.items_count,
            self.var_spec,
            self.remaining_bytes_len,
            self.syntax_id,
            self.transport_size,
            self.num_elements,
            self.db_number,
            self.area_type,
        )

        result = bytearray()
        result.extend(struct.pack(">BBBBBBHHB", *elements))

        # There are 3 bytes for the area offset, need to treat it in a "special way"
        offset = struct.pack(">L", self.area_offset)
        result.extend(offset[1:])
        return result


class ReadAreaResponseHeader(ProtocolObject):
    def __init__(self):
        super(ReadAreaResponseHeader, self).__init__()
        self.fun_read = 0x00
        self.item_count = 0x00
        self.items = ReadAreaResponseItem()

    def from_bytes(self, b):
        (
            self.fun_read,
            self.item_count,
        ) = struct.unpack(">BB", b[0:2])
        self.items.from_bytes(b[2:])

    def to_bytes(self):
        elements = (
            self.fun_read,
            self.item_count,
        )
        result = bytearray()
        result.extend(struct.pack(">BB", *elements))
        result.extend(self.items.to_bytes())
        return result


class ReadAreaResponseItem(ProtocolObject):
    def __init__(self):
        super(ReadAreaResponseItem, self).__init__()
        self.return_code = 0x00
        self.transport_size = 0x00
        self.data_length = 0x0000
        self.payload = bytearray()

    def from_bytes(self, b):
        (
            self.return_code,
            self.transport_size,
            self.data_length,
        ) = struct.unpack(">BBH", b[0:4])
        self.payload[:] = b[4:]

    def to_bytes(self):
        elements = (
            self.return_code,
            self.transport_size,
            self.data_length,
        )
        result = bytearray()
        result.extend(struct.pack(">BBH", *elements))
        result.extend(self.payload)
        return result





class WriteAreaRequestItem(ProtocolObject):
    def __init__(self):
        super(WriteAreaRequestItem, self).__init__()
        self.ReturnCode = 0x00
        self.TransportSize = 0x00
        self.DataLength = 0x0000
        self.data = bytearray()

    def from_bytes(self, b):
        (
            self.ReturnCode,
            self.TransportSize,
            self.DataLength,
        ) = struct.unpack(">BBH", b[0:4])
        self.data[:] = b[4:]

    def to_bytes(self):
        elements = (
            self.ReturnCode,
            self.TransportSize,
            self.DataLength,
        )
        result = bytearray()
        result.extend(struct.pack(">BBH", *elements))
        result.extend(self.data)
        return result

class WriteAreaRequestParameters(ProtocolObject):
    def __init__(self, payload: WriteAreaRequestItem):
        super(WriteAreaRequestParameters, self).__init__()
        self.var_spec = 0x12
        self.remaining_bytes_len = 0x0a
        self.syntax_id = 0x10
        self.TransportSize = 0x00
        self.Length = 0x0000
        self.DBNumber = 0x0000
        self.Area = 0x00
        self.Address = 0x000000
        self.payload = payload

    def from_bytes(self, b):
        (
            self.var_spec,
            self.remaining_bytes_len,
            self.syntax_id,
            self.TransportSize,
            self.Length,
            self.DBNumber,
            self.Area,
        ) = struct.unpack(">BBBBHHB", b[0:9])
        tmp_address = bytearray(4)
        tmp_address[1:4] = b[9:12]
        self.Address = struct.unpack(">L", tmp_address)
        self.payload.from_bytes(b[12:])

    def to_bytes(self):
        elements = (
            self.var_spec,
            self.remaining_bytes_len,
            self.syntax_id,
            self.TransportSize,
            self.Length,
            self.DBNumber,
            self.Area,
        )
        result = bytearray()
        result.extend(struct.pack(">BBBBHHB", *elements))
        tmp_address = struct.pack(">L", self.Address)
        result.extend(tmp_address[1:])
        result.extend(self.payload.to_bytes())
        return result


class WriteAreaRequest(ProtocolObject):
    def __init__(self, payload: WriteAreaRequestParameters):
        super(WriteAreaRequest, self).__init__()
        self.FunWrite = 0x05
        self.ItemsCount = 0x01
        self.payload = payload

    def from_bytes(self, b):
        if len(b) >= 2:
            (
                self.FunWrite,
                self.ItemsCount,
            ) = struct.unpack(">BB", b[0:2])
            self.payload.from_bytes(b[2:])

    def to_bytes(self):
        elements = (
            self.FunWrite,
            self.ItemsCount,
        )
        result = bytearray()
        result.extend(struct.pack(">BB", *elements))
        result.extend(self.payload.to_bytes())
        return result


class WriteAreaResponse(ProtocolObject):
    def __init__(self):
        super(WriteAreaResponse, self).__init__()
        self.FunWrite = 0x00
        self.ItemCount = 0x00
        self.Data = bytearray()

    def from_bytes(self, b):
        if len(b) >= 2:
            (
                self.FunWrite,
                self.ItemCount,
            ) = struct.unpack(">BB", b[0:2])
            self.Data = b[2:]

    def to_bytes(self):
        elements = (
            self.FunWrite,
            self.ItemCount,
        )
        result = bytearray()
        result.extend(struct.pack(">BB", *elements))
        result.extend(self.Data)
        return result