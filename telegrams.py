import struct
import logging
import utils
import S7

log = logging.getLogger(__file__)

class PduTypes(object):
    ConnectionRequest = 0xE0
    ConnectionConfirm = 0xD0
    DisconnectRequest = 0x80
    DisconnectConfirm = 0xC0
    DataTransfer = 0xF0
    EndOfTransmission = 0x80
    ExpeditedData = 0x10
    ExpeditedDataAck = 0x20
    CLTP_UD = 0x40
    Reject = 0x50
    AckData = 0x70

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


class TpktTransport(object):
    def __init__(self, socket):
        self.socket = socket
        self.length = 0
        self.payload = bytearray()

    def send(self, payload, version=3, reserved=0):
        packet = bytearray(4)
        packet[0:1] = struct.pack(">B", version)
        packet[1:2] = struct.pack(">B", reserved)
        self.length = len(packet) + len(payload)
        packet[2:4] = struct.pack(">H", self.length)

        log.debug("TPKT Send Header:")
        log.debug(utils.hex_log(packet))

        self.payload = payload
        packet.extend(self.payload)

        log.debug("TPKT Full Packet:")
        log.debug(utils.hex_log(packet))

        self.socket.send(packet)

    def recv(self):
        header = self.socket.recv(4)
        self.length = struct.unpack(">H", header[2:4])[0]

        log.debug("TPKT Recv Header:")
        log.debug(utils.hex_log(header))


        self.payload[:] = self.socket.recv(self.length)

        log.debug("TPKT Recv Full Payload:")
        log.debug(utils.hex_log(self.payload))

        return self.payload


class CoptParams(object):
    def __init__(self, socket):
        self.cotp = CotpControlTransport(socket)
        pass

    def iso_connection_request(self, local_tsap, remote_tsap):
        tsap = bytearray(8)
        tsap[0] = 0xC1
        tsap[1] = 0x02
        tsap[2:4] = struct.pack(">H", local_tsap)
        tsap[4] = 0xC2
        tsap[5] = 0x02
        tsap[6:8] = struct.pack(">H", remote_tsap)

        log.debug("TSAP:")
        log.debug(utils.hex_log(tsap))

        self.send(tsap, pdu_type=PduTypes.ConnectionRequest)
        self.recv()
        if self.cotp.pdu_type == PduTypes.ConnectionConfirm:
            return True
        else:
            return False

    def send(self,tsap, pdu_type, pdu_size_code=0xC0, pdu_size_len=0x01, pdu_size_val=PduSizeValues.Size_2048):
        packet = bytearray(3)
        packet[0:1] = struct.pack(">B", pdu_size_code)
        packet[1:2] = struct.pack(">B", pdu_size_len)
        packet[2:3] = struct.pack(">B", pdu_size_val)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(tsap)
        self.cotp.send(copt_params=packet, pdu_type=pdu_type)

    def recv(self):
        response = self.cotp.recv()
        return response


class CotpControlTransport(object):
    def __init__(self, socket):
        self.tpkt = TpktTransport(socket)
        self.pdu_type = 0
        self.dst_ref = 0
        self.src_ref = 0
        self.co_r = 0
        self.copt_params = None
        self.h_length = 0

    def send(self, copt_params, pdu_type, dst_ref=0, src_ref=0, co_r=0b01000000):
        self.copt_params = copt_params
        self.pdu_type = pdu_type
        self.dst_ref = dst_ref
        self.src_ref = src_ref
        self.co_r = co_r

        self.h_length = 6 + len(copt_params) # Header length : initialized to 6 (length without params - 1)
        packet = bytearray(8)
        packet[0:1] = struct.pack(">B", self.h_length)
        packet[1:2] = struct.pack(">B", pdu_type)
        packet[2:4] = struct.pack(">B", dst_ref)
        packet[4:6] = struct.pack(">B", src_ref)
        packet[6:7] = struct.pack(">B", co_r)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(copt_params)
        self.tpkt.send(packet)


    def recv(self):
        packet = self.tpkt.recv()
        self.h_length = struct.unpack(">B", packet[0:1])[0]
        self.pdu_type = struct.unpack(">B", packet[1:2])[0]
        self.dst_ref = struct.unpack(">H", packet[2:4])[0]
        self.src_ref = struct.unpack(">H", packet[4:6])[0]
        self.co_r = struct.unpack(">B", packet[6:7])[0]
        return packet[7:]

class CotpDataTransport(object):
    def __init__(self, socket):
        self.tpkt = TpktTransport(socket)
        self.h_length = 2
        self.pdu_type = PduTypes.DataTransfer
        self.eot_num = 0x80

    def send(self, payload):
        packet = bytearray(3)
        packet[0:1] = struct.pack(">B", self.h_length)
        packet[1:2] = struct.pack(">B", self.pdu_type)
        packet[2:3] = struct.pack(">B", self.eot_num)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(payload)
        self.tpkt.send(packet)

    def recv(self):
        packet = self.tpkt.recv()
        self.h_length = struct.unpack(">B", packet[0:1])[0]
        self.pdu_type = struct.unpack(">B", packet[1:2])[0]
        self.eot_num = struct.unpack(">B", packet[2:3])[0]
        return packet[3:]


# class S7Request(object):
#     def __init__(self, socket):
#         self.cotp = CotpDataTransport(socket)
#
#         self.p = 0x32           # Telegram ID, always 0x32
#         self.pdu_type = 1       # Header Type 1 or 7 AKA Job Type
#         self.ab_ex = 0x0000     # AB currently unknown, maybe it can be used for long numbers. AKA Redundancy
#         self.sequence = 0x0400  # Message ID. This can be used to make sure a received answer AKA Pdu Reference
#         self.par_len = 0        # Length of parameters which follow this header
#         self.data_len = 0       # Length of data which follow the parameters
#
#     def send(self, data, par_len, data_len, p=0x32, pdu_type=1, ab_ex=0, sequence=0x0400):
#         self.p = p
#         self.pdu_type = pdu_type
#         self.ab_ex = ab_ex
#         self.sequence = sequence
#         self.par_len = par_len
#         self.data_len = data_len
#
#         packet = bytearray(10)
#         packet[0:1] = struct.pack(">B", self.p)
#         packet[1:2] = struct.pack(">B", self.pdu_type)
#         packet[2:4] = struct.pack(">H", self.ab_ex)
#         packet[4:6] = struct.pack(">H", self.sequence)
#         packet[6:8] = struct.pack(">H", self.par_len)
#         packet[8:10] = struct.pack(">H", self.data_len)
#
#         log.debug("{} Header:".format(self.__class__.__name__))
#         log.debug(utils.hex_log(packet))
#
#         packet.extend(data)
#         self.cotp.send(packet)
#
#
#     def recv(self):
#         packet = self.cotp.recv()
#         log.debug("S7 Response:")
#         log.debug(utils.hex_log(packet))
#         return packet[10:]


class NegotiateParams(object):
    def __init__(self, socket):
        self.s7 = S7Response23(socket)
        self.fun_negotiate = PduFunctions.pduNegotiate
        self.unknown = 0
        self.parallel_jobs_1 = 0x0001
        self.parallel_jobs_2 = 0x0001
        self.pdu_length = 480                   # Requested length for the negotiation
        self.negotiated_pdu_length = 480        # Confirmed length for the negotiation

    def negotiate(self, pdu_length=480):
        self.pdu_length = pdu_length

        packet = bytearray(8)
        packet[0:1] = struct.pack(">B", self.fun_negotiate)
        packet[1:2] = struct.pack(">B", self.unknown)
        packet[2:4] = struct.pack(">H", self.parallel_jobs_1)
        packet[4:6] = struct.pack(">H", self.parallel_jobs_2)
        packet[6:8] = struct.pack(">H", self.pdu_length)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.s7.send(packet, par_len=len(packet), data_len=0)

        response = self.s7.recv()
        log.debug("Parameters negotiation response:")
        log.debug(utils.hex_log(response))

        self.fun_negotiate = struct.unpack(">B", packet[0:1])[0]
        self.unknown = struct.unpack(">B", packet[1:2])[0]
        self.parallel_jobs_1 = struct.unpack(">H", packet[2:4])[0]
        self.parallel_jobs_2 = struct.unpack(">H", packet[4:6])[0]
        self.negotiated_pdu_length = struct.unpack(">H", packet[6:8])[0]

        return self.negotiated_pdu_length == self.pdu_length


class AreaFunctionRequest(object):
    def __init__(self, socket):
        self.s7 = S7Response23(socket)
        self.function = 4 # 4 read, 5 write
        self.items_count = 1
        self.var_spec = 0x12
        self.remaining_bytes_len = 0x0a
        self.syntax_id = 0x10

    def send(self, payload, function):
        self.function = function
        self.items_count = 1
        self.var_spec = 0x12
        self.remaining_bytes_len = 0x0a
        self.syntax_id = 0x10
        packet = bytearray(5)
        packet[0:1] = struct.pack(">B", self.function)
        packet[1:2] = struct.pack(">B", self.items_count)
        packet[2:3] = struct.pack(">B", self.var_spec)
        packet[3:4] = struct.pack(">B", self.remaining_bytes_len)
        packet[4:5] = struct.pack(">B", self.syntax_id)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(payload)
        self.s7.send(data=packet, par_len=len(packet), data_len=0)


class AreaTransferFunctions(object):
    def __init__(self, socket, pdu_length):
        self.pdu_length = pdu_length

        self.function_request = AreaFunctionRequest(socket)
        self.read_response = FunctionItem(socket)

        self.transport_size = 0x00
        self.num_elements = 0x0000
        self.db_number = 0x0000
        self.area_type = 0x00
        self.area_offset = 0x000000 # 3 bytes in size

    def read(self, area, db, start, num_elements, elements_type):
        self.num_elements = num_elements
        self.db_number = db
        self.area_type = area

        if area is S7.Area.CT:
            elements_type = S7.DataTypes.Counter
        if area is S7.Area.TM:
            elements_type = S7.DataTypes.Timer

        # Calc Word size
        self.transport_size = S7.data_size(elements_type)
        if self.transport_size == 0:
            raise Exception("Invalid elements_type given")

        tot_elements = num_elements
        if elements_type == S7.DataTypes.Bit:
            tot_elements = 1  # Only 1 bit can be transferred at time
        else:
            if (elements_type != S7.DataTypes.Counter) and (elements_type != S7.DataTypes.Timer):
                tot_elements = tot_elements * self.transport_size
                self.transport_size = 1
                elements_type = S7.DataTypes.Byte

        max_elements = (self.pdu_length - 18) // self.transport_size

        result = bytearray()
        while tot_elements > 0:
            num_elements = min(tot_elements, max_elements)

            area_offset = start

            no_shift_areas = (
                S7.DataTypes.Bit,
                S7.DataTypes.Counter,
                S7.DataTypes.Timer,
            )
            if area_offset not in no_shift_areas:
                area_offset = (area_offset << 3)

            packet = bytearray(9)
            packet[0:1] = struct.pack(">B", elements_type)
            packet[1:3] = struct.pack(">H", num_elements)
            packet[3:5] = struct.pack(">H", self.db_number)
            packet[5:6] = struct.pack(">B", self.area_type)
            packet[6:9] = struct.pack(">L", area_offset)[1:4]

            log.debug("{} Header:".format(self.__class__.__name__))
            log.debug(utils.hex_log(packet))

            self.function_request.send(packet, function=4)

            # Read with the response header
            response = self.read_response.recv()
            result.extend(response)

            tot_elements -= num_elements
            start += num_elements * self.transport_size

        return result

    def write(self, area, db, start, num_elements, elements_type, data):
        self.num_elements = num_elements
        self.db_number = db
        self.area_type = area

        if area is S7.Area.CT:
            elements_type = S7.DataTypes.Counter
        if area is S7.Area.TM:
            elements_type = S7.DataTypes.Timer

        # Calc Word size
        self.transport_size = S7.data_size(elements_type)
        if self.transport_size == 0:
            raise Exception("Invalid elements_type given")

        tot_elements = num_elements
        if elements_type == S7.DataTypes.Bit:
            tot_elements = 1  # Only 1 bit can be transferred at time
        else:
            if (elements_type != S7.DataTypes.Counter) and (elements_type != S7.DataTypes.Timer):
                tot_elements = tot_elements * self.transport_size
                self.transport_size = 1
                elements_type = S7.DataTypes.Byte

        max_elements = (self.pdu_length - 18) // self.transport_size

        result = bytearray()
        while tot_elements > 0:
            num_elements = min(tot_elements, max_elements)

            area_offset = start

            no_shift_areas = (
                S7.DataTypes.Bit,
                S7.DataTypes.Counter,
                S7.DataTypes.Timer,
            )
            if area_offset not in no_shift_areas:
                area_offset = (area_offset << 3)


            packet = bytearray(9)
            packet[0:1] = struct.pack(">B", elements_type)
            packet[1:3] = struct.pack(">H", num_elements)
            packet[3:5] = struct.pack(">H", self.db_number)
            packet[5:6] = struct.pack(">B", self.area_type)
            packet[6:9] = struct.pack(">L", area_offset)[1:4]

            log.debug("{} Header:".format(self.__class__.__name__))
            log.debug(utils.hex_log(packet))

            self.function_request.send(packet, function=4)

            # Read with the response header
            response = self.read_response.recv()
            result.extend(response)

            tot_elements -= num_elements
            start += num_elements * self.transport_size

        return result


class S7Response23(object):
    def __init__(self, socket):
        self.cotp = CotpDataTransport(socket)

        self.p = 0x32  # Telegram ID, always 0x32
        self.pdu_type = 1  # Header Type 1 or 7 AKA Job Type
        self.ab_ex = 0x0000  # AB currently unknown, maybe it can be used for long numbers. AKA Redundancy
        self.sequence = 0x3900  # Message ID. This can be used to make sure a received answer AKA Pdu Reference
        self.par_len = 0  # Length of parameters which follow this header
        self.data_len = 0  # Length of data which follow the parameters
        self.error = 0x00

    def send(self, data, par_len, data_len, p=0x32, pdu_type=1, ab_ex=0, sequence=0x0400):
        self.p = p
        self.pdu_type = pdu_type
        self.ab_ex = ab_ex
        self.sequence = sequence
        self.par_len = par_len
        self.data_len = data_len
        self.error = 0x0000

        packet = bytearray(10)
        packet[0:1] = struct.pack(">B", self.p)
        packet[1:2] = struct.pack(">B", self.pdu_type)
        packet[2:4] = struct.pack(">H", self.ab_ex)
        packet[4:6] = struct.pack(">H", self.sequence)
        packet[6:8] = struct.pack(">H", self.par_len)
        packet[8:10] = struct.pack(">H", self.data_len)
        # packet[10:12] = struct.pack(">H", self.error)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(data)
        self.cotp.send(packet)

    def recv(self):
        packet = self.cotp.recv()

        log.debug("{} Response:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.p = struct.unpack(">B", packet[0:1])[0]
        self.pdu_type = struct.unpack(">B", packet[1:2])[0]
        self.ab_ex = struct.unpack(">H", packet[2:4])[0]
        self.sequence = struct.unpack(">H", packet[4:6])[0]
        self.par_len = struct.unpack(">H", packet[6:8])[0]
        self.data_len = struct.unpack(">H", packet[8:10])[0]
        self.error = struct.unpack(">H", packet[10:12])[0]

        return packet[12:]

class FunctionParameters(object):
    def __init__(self, socket):
        self.s7 = S7Response23(socket)
        self.function_code = 0x00
        self.item_count = 0x00

    def send(self, function_code, item_count, payload):
        self.function_code = function_code
        self.item_count = item_count
        packet = bytearray(2)
        packet[0:1] = struct.pack(">B", self.function_code)
        packet[1:2] = struct.pack(">B", self.item_count)
        packet.extend(payload)

    def recv(self):
        packet = self.s7.recv()
        self.function_code = struct.unpack(">B", packet[0:1])[0]
        self.item_count = struct.unpack(">B", packet[1:2])[0]

        log.debug("{} Response:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        return packet[2:]

class FunctionItem(object):
    def __init__(self, socket):
        self.parameters = FunctionParameters(socket)

        self.return_code = 0x00
        self.transport_size = 0x00
        self.data_length = 0x0000
        self.payload = bytearray()

    def send(self, transport_size, data_length, payload):
        self.return_code = 0x00
        self.transport_size = transport_size
        self.data_length = data_length
        packet = bytearray(4)
        packet[0:1] = struct.pack(">B", self.return_code)
        packet[1:2] = struct.pack(">B", self.transport_size)
        packet[2:4] = struct.pack(">H", self.data_length)
        packet.extend(payload)
        self.parameters.send(function_code=5, item_count=1, payload=packet)

    def recv(self):
        packet = self.parameters.recv()
        self.return_code = struct.unpack(">B", packet[0:1])[0]
        self.transport_size = struct.unpack(">B", packet[1:2])[0]
        self.data_length = struct.unpack(">H", packet[2:4])[0]
        if self.transport_size not in (S7.ResultTransportSizes.TS_ResOctet,
                                       S7.ResultTransportSizes.TS_ResReal,
                                       S7.ResultTransportSizes.TS_ResBit):
            self.data_length = self.data_length >> 3

        log.debug("{} Response:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))


        self.payload = packet[4:]
        return self.payload




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
        self.TransportSize = 0x00
        self.Length = 0x0000
        self.DBNumber = 0x0000
        self.Area = 0x00
        self.Address = 0x000000
        self.payload = payload

    def from_bytes(self, b):
        (
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