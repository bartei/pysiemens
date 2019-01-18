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


class TpktTransport(object):
    def __init__(self, socket):
        self.socket = socket
        self.length = 0
        self.data = bytearray()

    def send(self, data, version=3, reserved=0):
        packet = bytearray(4)
        packet[0:1] = struct.pack(">B", version)
        packet[1:2] = struct.pack(">B", reserved)
        self.length = len(packet) + len(data)
        packet[2:4] = struct.pack(">H", self.length)

        log.debug("{} sends header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.data = data
        packet.extend(self.data)

        log.debug("{} sends full packet:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.socket.send(packet)

    def recv(self):
        packet = self.socket.recv(4)
        self.length = struct.unpack(">H", packet[2:4])[0]

        log.debug("{} receives header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.data[:] = self.socket.recv(self.length)

        log.debug("{} receives data:".format(self.__class__.__name__))
        log.debug(utils.hex_log(self.data))


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

    def send(self, tsap, pdu_type, pdu_size_code=0xC0, pdu_size_len=0x01, pdu_size_val=PduSizeValues.Size_2048):
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
        packet = self.tpkt.data
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
        self.data = bytearray()

    def send(self, data):
        self.data = data

        packet = bytearray(3)
        packet[0:1] = struct.pack(">B", self.h_length)
        packet[1:2] = struct.pack(">B", self.pdu_type)
        packet[2:3] = struct.pack(">B", self.eot_num)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(self.data)
        self.tpkt.send(packet)

    def recv(self):
        self.tpkt.recv()
        packet = self.tpkt.data
        self.h_length = struct.unpack(">B", packet[0:1])[0]
        self.pdu_type = struct.unpack(">B", packet[1:2])[0]
        self.eot_num = struct.unpack(">B", packet[2:3])[0]
        self.data[:] = packet[3:]


class S7Header(object):
    def __init__(self, socket):
        self.cotp = CotpDataTransport(socket)

        self.p = 0x32  # Telegram ID, always 0x32
        self.pdu_type = 1  # Header Type 1 or 7 AKA Job Type
        self.ab_ex = 0x0000  # AB currently unknown, maybe it can be used for long numbers. AKA Redundancy
        self.sequence = 0x3900  # Message ID. This can be used to make sure a received answer AKA Pdu Reference
        self.par_len = 0  # Length of parameters which follow this header
        self.data_len = 0  # Length of data which follow the parameters
        self.error = 0x00

        self.parameters = bytearray()
        self.data = bytearray()

    def send(self, parameters, data, p=0x32, pdu_type=1, ab_ex=0, sequence=0x0500):
        self.p = p
        self.pdu_type = pdu_type
        self.ab_ex = ab_ex
        self.sequence = sequence
        self.par_len = len(parameters)
        self.data_len = len(data)

        self.parameters[:] = parameters
        self.data = data[:] = data

        packet = bytearray(10)
        packet[0:1] = struct.pack(">B", self.p)
        packet[1:2] = struct.pack(">B", self.pdu_type)
        packet[2:4] = struct.pack(">H", self.ab_ex)
        packet[4:6] = struct.pack(">H", self.sequence)
        packet[6:8] = struct.pack(">H", len(self.parameters))
        packet[8:10] = struct.pack(">H", len(self.data))

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(self.parameters)
        packet.extend(self.data)
        self.cotp.send(packet)

    def recv(self):
        self.cotp.recv()
        packet = self.cotp.data

        log.debug("{} Response:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.p = struct.unpack(">B", packet[0:1])[0]
        self.pdu_type = struct.unpack(">B", packet[1:2])[0]
        self.ab_ex = struct.unpack(">H", packet[2:4])[0]
        self.sequence = struct.unpack(">H", packet[4:6])[0]
        self.par_len = struct.unpack(">H", packet[6:8])[0]
        self.data_len = struct.unpack(">H", packet[8:10])[0]
        self.error = struct.unpack(">H", packet[10:12])[0]

        self.parameters[:] = packet[12:12+self.par_len]
        self.data[:] = packet[12+self.par_len:12+self.par_len+self.data_len]


class NegotiateParams(object):
    def __init__(self, socket):
        self.s7 = S7Header(socket)
        self.function = PduFunctions.pduNegotiate
        self.unknown = 0
        self.parallel_jobs_1 = 0x0001
        self.parallel_jobs_2 = 0x0001
        self.pdu_length = 480                   # Requested length for the negotiation
        self.negotiated_pdu_length = 480        # Confirmed length for the negotiation

    def negotiate(self, pdu_length=480):
        self.pdu_length = pdu_length

        packet = bytearray(8)
        packet[0:1] = struct.pack(">B", self.function)
        packet[1:2] = struct.pack(">B", self.unknown)
        packet[2:4] = struct.pack(">H", self.parallel_jobs_1)
        packet[4:6] = struct.pack(">H", self.parallel_jobs_2)
        packet[6:8] = struct.pack(">H", self.pdu_length)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.s7.send(parameters=packet, data=bytearray(0))

        self.s7.recv()
        res_header = self.s7.parameters
        res_data = self.s7.data

        log.debug("{} Response Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(res_header))

        log.debug("{} Response Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(res_data))

        self.function = struct.unpack(">B", res_header[0:1])[0]
        self.unknown = struct.unpack(">B", res_header[1:2])[0]
        self.parallel_jobs_1 = struct.unpack(">H", res_header[2:4])[0]
        self.parallel_jobs_2 = struct.unpack(">H", res_header[4:6])[0]
        self.negotiated_pdu_length = struct.unpack(">H", res_header[6:8])[0]

        return self.negotiated_pdu_length == self.pdu_length


class AreaFunctionRequest(object):
    def __init__(self, socket):
        self.s7 = S7Header(socket)
        self.function = 4  # 4 read, 5 write
        self.items_count = 1
        self.var_spec = 0x12
        self.remaining_bytes_len = 0x0a
        self.syntax_id = 0x10

    def send(self, function, parameters, data):
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

        log.debug("{} sends:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        packet.extend(parameters)
        par_len = len(packet)
        packet.extend(data)
        self.s7.send(data=packet, par_len=par_len, data_len=len(data))

    def recv(self):
        packet = self.s7.recv()
        log.debug("{} recv packet:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))
        return packet


class AreaTransferFunctions(object):
    def __init__(self, socket):
        self.function_request = AreaFunctionRequest(socket)
        self.socket = socket

        self.transport_size = 0x00
        self.num_elements = 0x0000
        self.db_number = 0x0000
        self.area_type = 0x00
        self.area_offset = 0x000000 # 3 bytes in size

    def send(self, function_code, area, db, offset, elements_count, elements_type, payload):
        packet = bytearray(9)
        packet[0:1] = struct.pack(">B", elements_type)
        packet[1:3] = struct.pack(">H", elements_count)
        packet[3:5] = struct.pack(">H", db)
        packet[5:6] = struct.pack(">B", area)
        packet[6:9] = struct.pack(">L", offset)[1:4]

        log.debug("{} sends header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        log.debug("{} sends data:".format(self.__class__.__name__))
        log.debug(utils.hex_log(payload))

        self.function_request.send(function=function_code, parameters=packet, data=payload)

    def recv(self):
        packet = self.function_request.recv()
        log.debug("{} recv packet:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))
        return packet


class FunctionParameters(object):
    def __init__(self, socket):
        self.transfer_runctions = AreaTransferFunctions(socket)
        self.function_code = 0x00
        self.item_count = 0x00

    def send(self, function_code, item_count, area, db, offset, elements_count, elements_type, payload):
        self.function_code = function_code
        self.item_count = item_count
        packet = bytearray(2)
        packet[0:1] = struct.pack(">B", self.function_code)
        packet[1:2] = struct.pack(">B", self.item_count)
        packet.extend(payload)

        log.debug("{} sends:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))


        self.transfer_runctions.send(function_code=function_code, area=area, db=db, offset=offset,
                                     elements_count=elements_count, elements_type=elements_type, payload=payload)

    def recv(self):
        packet = self.transfer_runctions.recv()
        self.function_code = struct.unpack(">B", packet[0:1])[0]
        self.item_count = struct.unpack(">B", packet[1:2])[0]

        log.debug("{} receives:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        return packet[2:]

class FunctionItem(object):
    def __init__(self, socket):
        self.parameters = FunctionParameters(socket)

        self.return_code = 0x00
        self.transport_size = 0x00
        self.data_length = 0x0000
        self.payload = bytearray()

    def send(self, data_length, area, db, offset, elements_count, elements_type, payload):
        self.return_code = 0x00
        self.transport_size =  S7.transport_size(elements_type)

        # Adjust offset and data length
        no_shift_areas = (
            S7.DataTypes.Bit,
            S7.DataTypes.Counter,
            S7.DataTypes.Timer,
        )
        if offset not in no_shift_areas:
            offset = (offset << 3)
            data_length = data_length << 3

        self.data_length = data_length

        packet = bytearray(4)
        packet[0:1] = struct.pack(">B", self.return_code)
        packet[1:2] = struct.pack(">B", self.transport_size)
        packet[2:4] = struct.pack(">H", self.data_length)
        packet.extend(payload)

        log.debug("{} sends:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))


        self.parameters.send(function_code=5, item_count=1, area=area, db=db, offset=offset,
                             elements_count=elements_count, elements_type=elements_type, payload=packet)

    def recv(self):
        packet = self.parameters.recv()

        # When doing a write request, the content of this packet is the error code of the operation
        if len(packet) == 1:
            self.return_code = struct.unpack(">B", packet[0:1])[0]
            return self.return_code

        self.return_code = struct.unpack(">B", packet[0:1])[0]
        self.transport_size = struct.unpack(">B", packet[1:2])[0]
        self.data_length = struct.unpack(">H", packet[2:4])[0]

        # Adjust Offset
        if self.transport_size not in (S7.TransportSizes.Octet,
                                       S7.TransportSizes.Real,
                                       S7.TransportSizes.Bit):
            self.data_length = self.data_length >> 3

        log.debug("{} receives:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        self.payload = packet[4:]
        return self.payload


class Functions(object):
    def __init__(self, socket, pdu_length):
        self.functions = AreaTransferFunctions(socket)
        self.pdu_length = pdu_length
        self.socket = socket

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

            self.functions.send(function_code=4, area=self.area_type, db=self.db_number,offset=area_offset,
                                elements_count=num_elements,elements_type=elements_type, payload=b'')

            # Read with the response header
            response_item = FunctionItem(self.socket)
            response = response_item.recv()
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

        while tot_elements > 0:
            num_elements = min(tot_elements, max_elements)

            area_offset = start

            item = FunctionItem(self.socket)
            item.send(
                data_length=len(data),
                area=area,
                db=self.db_number,
                offset=area_offset,
                elements_count=num_elements,
                elements_type=elements_type,
                payload=data
            )

            response_item = FunctionItem(self.socket)
            result = response_item.recv()

            tot_elements -= num_elements
            start += num_elements * self.transport_size

        return
