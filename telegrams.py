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
        self.tpkt.recv()
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

        self.parameters = bytearray()
        self.data = bytearray()

    def send(self, parameters, data, p=0x32, pdu_type=1, ab_ex=0):
        sequence = 0x0500

        self.parameters[:] = parameters
        self.data = data

        packet = bytearray(10)
        packet[0:1] = struct.pack(">B", p)
        packet[1:2] = struct.pack(">B", pdu_type)
        packet[2:4] = struct.pack(">H", ab_ex)
        packet[4:6] = struct.pack(">H", sequence)
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

        result = dict()
        result['p'] = struct.unpack(">B", packet[0:1])[0]
        result['pdu_type'] = struct.unpack(">B", packet[1:2])[0]
        result['ab_ex'] = struct.unpack(">H", packet[2:4])[0]
        result['sequence'] = struct.unpack(">H", packet[4:6])[0]

        if result['pdu_type'] == 8:
            data_len = struct.unpack(">H", packet[6:8])[0]
            result['data_len'] = data_len
            result['error'] = struct.unpack(">H", packet[8:10])[0]
            result['parameters'] = bytearray(0)
            result['data'] = packet[10:10+data_len]

        if result['pdu_type'] in (1, 7, ):
            par_len = struct.unpack(">H", packet[6:8])[0]
            data_len = struct.unpack(">H", packet[8:10])[0]
            result['par_len'] = par_len
            result['data_len'] = data_len
            result['parameters'] = packet[10:10+par_len]
            result['data'] = packet[10+par_len:10+par_len+data_len]

        if result['pdu_type'] in (2, 3, ):
            par_len = struct.unpack(">H", packet[6:8])[0]
            data_len = struct.unpack(">H", packet[8:10])[0]
            result['par_len'] = par_len
            result['data_len'] = data_len
            result['error'] = struct.unpack(">H", packet[10:12])[0]
            result['parameters'] = packet[12:12+par_len]
            result['data'] = packet[12+par_len:12+par_len+data_len]

        return result


class S7Functions(object):
    pdu_functions = dict({
        'pduResponse': 0x02,  # Response (when error)
        'pduFuncRead': 0x04,  # Read area
        'pduFuncWrite': 0x05,  # Write area
        'pduNegotiate': 0xF0,  # Negotiate PDU length
        'pduStart': 0x28,  # CPU start
        'pduStop': 0x29,  # CPU stop
        'pduStartUpload': 0x1D,  # Start Upload
        'pduUpload': 0x1E,  # Upload
        'pduEndUpload': 0x1F,  # EndUpload
        'pduReqDownload': 0x1A,  # Start Download request
        'pduDownload': 0x1B,  # Download request
        'pduDownloadEnded': 0x1C,  # Download end request
        'pduControl': 0x28  # Control (insert/delete..)
    })

    pdu_sub_functions = dict({
        'SFun_ListAll': 0x01,  # List all blocks
        'SFun_ListBoT': 0x02,  # List Blocks of type
        'SFun_BlkInfo': 0x03,  # Get Block info
        'SFun_ReadSZL': 0x01,  # Read SZL
        'SFun_ReadClock': 0x01,  # Read Clock (Date and Time)
        'SFun_SetClock': 0x02,  # Set Clock (Date and Time)
        'SFun_EnterPwd': 0x01,  # Enter password    for this session
        'SFun_CancelPwd': 0x02,  # Cancel password    for this session
        'SFun_Insert': 0x50,  # Insert block
        'SFun_Delete': 0x42,  # Delete block
    })

    types_groups = dict({
        'grProgrammer': 0x41,
        'grCyclicData': 0x42,
        'grBlocksInfo': 0x43,
        'grSZL': 0x44,
        'grPassword': 0x45,
        'grBSend': 0x46,
        'grClock': 0x47,
        'grSecurity': 0x45,
    })

    def __init__(self, socket):
        self.socket = socket
        self.pdu_length = 240

    @staticmethod
    def shift_value(value, data_type):
        # Adjust offset and data length
        no_shift_data_types = (
            S7.DataTypes.Bit,
            S7.DataTypes.Counter,
            S7.DataTypes.Timer,
        )

        if data_type not in no_shift_data_types:
            return value << 3
        else:
            return value

    @staticmethod
    def unshift_value(value, data_type):
        # Adjust offset and data length
        no_shift_data_types = (
            S7.DataTypes.Bit,
            S7.DataTypes.Counter,
            S7.DataTypes.Timer,
        )

        if data_type not in no_shift_data_types:
            return value >> 3
        else:
            return value

    def negotiate(self, pdu_length=480):
        function_code = self.pdu_functions["pduNegotiate"]
        unknown = 0
        parallel_jobs_1 = 0x0001
        parallel_jobs_2 = 0x0001
        pdu_length = pdu_length      # Requested length for the negotiation

        packet = bytearray(8)
        packet[0:1] = struct.pack(">B", function_code)
        packet[1:2] = struct.pack(">B", unknown)
        packet[2:4] = struct.pack(">H", parallel_jobs_1)
        packet[4:6] = struct.pack(">H", parallel_jobs_2)
        packet[6:8] = struct.pack(">H", pdu_length)

        log.debug("{} Header:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        request = S7Header(socket=self.socket)
        request.send(parameters=packet, data=bytearray(0))

        response = S7Header(socket=self.socket).recv()

        result = dict()
        result['function'] = struct.unpack(">B", response['parameters'][0:1])[0]
        result['unknown'] = struct.unpack(">B", response['parameters'][1:2])[0]
        result['parallel_jobs_1'] = struct.unpack(">H", response['parameters'][2:4])[0]
        result['parallel_jobs_2'] = struct.unpack(">H", response['parameters'][4:6])[0]
        result['pdu_length'] = struct.unpack(">H", response['parameters'][6:8])[0]
        self.pdu_length = result['pdu_length']

        return result

    def read_raw(self, area, db, offset, elements_count, elements_type):
        raw_data_size = elements_count * S7.data_size(elements_type)
        if raw_data_size == 0:
            raise Exception("Invalid elements_type given")

        if raw_data_size > self.pdu_length - 18:
            raise Exception("Data size to be transferred exceeds pdu size")

        parameters = bytearray()
        parameters.extend(struct.pack(">B", self.pdu_functions["pduFuncRead"]))

        parameters.extend(struct.pack(">B", 1))
        parameters.extend(struct.pack(">B", 0x12))
        parameters.extend(struct.pack(">B", 0x0a))
        parameters.extend(struct.pack(">B", 0x10))

        parameters.extend(struct.pack(">B", S7.DataTypes.Byte))
        parameters.extend(struct.pack(">H", raw_data_size))
        parameters.extend(struct.pack(">H", db))
        parameters.extend(struct.pack(">B", area))
        parameters.extend(struct.pack(">L", self.shift_value(offset, elements_type))[1:4])

        request = S7Header(socket=self.socket)
        request.send(parameters=parameters, data=bytearray(0))

        response = S7Header(socket=self.socket).recv()

        # Read the response parameters
        result = dict()
        result['function'] = struct.unpack(">B", response['parameters'][0:1])[0]
        result['item_count'] = struct.unpack(">B", response['parameters'][1:2])[0]

        # Read the response item
        result['return_code'] = struct.unpack(">B", response['data'][0:1])[0]
        result['data'] = response['data'][4:]

        return result

    def write_raw(self, area, db, start, elements_type, data):
        if area is S7.Area.CT:
            elements_type = S7.DataTypes.Counter
        if area is S7.Area.TM:
            elements_type = S7.DataTypes.Timer

        if len(data) > self.pdu_length - 18:
            raise Exception("Data is to big for the pdu size")

        # Function Parameters
        parameters = bytearray()
        parameters.extend(struct.pack(">B", self.pdu_functions["pduFuncWrite"]))
        parameters.extend(struct.pack(">B", 1))             # Item Count
        parameters.extend(struct.pack(">B", 0x12))
        parameters.extend(struct.pack(">B", 0x0a))
        parameters.extend(struct.pack(">B", 0x10))

        parameters.extend(struct.pack(">B", elements_type))     # Transport Size
        parameters.extend(struct.pack(">H", len(data)))         # Length
        parameters.extend(struct.pack(">H", db))                # Db Number
        parameters.extend(struct.pack(">B", area))              # Area
        parameters.extend(struct.pack(">L", self.shift_value(start, elements_type))[1:4])   # Address

        # Item
        transport_size = S7.transport_size(elements_type)

        packet = bytearray()
        packet.extend(struct.pack(">B", 0x00))    # Return Code
        packet.extend(struct.pack(">B", transport_size))   # Transport Size
        packet.extend(struct.pack(">H", self.shift_value(len(data), elements_type)))
        packet.extend(data)

        log.debug("{} sends:".format(self.__class__.__name__))
        log.debug(utils.hex_log(packet))

        request = S7Header(socket=self.socket)
        request.send(parameters=parameters, data=packet)

        # Process Response
        response = S7Header(socket=self.socket).recv()

        result = list()
        result.append({
            'function': response['parameters'][0],
            'items_count': response['parameters'][1],
            'result_code': response['data'][0],
        })

        return result

    def plc_stop(self):
        parameters = bytearray()
        parameters.extend(struct.pack(">B", self.pdu_functions["pduStop"]))  # Function
        parameters.extend([0x00, 0x00, 0x00, 0x00, 0x00])  # 5 unknown bytes always at 0

        ascii_string = b'P_PROGRAM'
        parameters.extend(struct.pack(">B",len(ascii_string))) # Length of the next elements
        parameters.extend(ascii_string)

        request = S7Header(socket=self.socket)
        request.send(parameters=parameters, data=b'')

        # Process Response
        response = S7Header(socket=self.socket).recv()

        result = dict()
        result['function'] = response['parameters'][0]

        if len(response['parameters']) > 1:
            result['para'] = response['parameters'][1]
            result['already_stopped'] = response['parameters'][1] == 0x02

        return result

    def plc_hot_start(self):
        parameters = bytearray()
        parameters.extend(struct.pack(">B", self.pdu_functions["pduStart"]))  # Function
        parameters.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD])  # 7 unknown bytes always at 0
        parameters.extend(struct.pack(">H", 0))  # Length 1

        ascii_string = b'P_PROGRAM'
        parameters.extend(struct.pack(">B", len(ascii_string)))  # Length of the next elements, Length 2
        parameters.extend(ascii_string)

        request = S7Header(socket=self.socket)
        request.send(parameters=parameters, data=b'')

        # Process Response
        response = S7Header(socket=self.socket).recv()

        result = dict()
        result['function'] = response['parameters'][0]
        if len(response['parameters']) > 1:
            result['para'] = response['parameters'][1]
            result['already_started'] = response['parameters'][1] == 0x03

        return result

    def plc_cold_start(self):
        parameters = bytearray()
        parameters.extend(struct.pack(">B", self.pdu_functions["pduStart"]))  # Function
        parameters.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD])  # 7 unknown bytes always at 0

        subfunction = bytearray()
        subfunction.extend(struct.pack(">H", 0x4320))  # Cold Start Subfunction Parameter 0x4320

        # Subfunction parameters
        parameters.extend(struct.pack(">H", len(subfunction)))  # Length
        parameters.extend(subfunction)  # Subfunction parameters

        # Function Parameters
        ascii_string = b'P_PROGRAM'
        parameters.extend(struct.pack(">B", len(ascii_string)))  # Length
        parameters.extend(ascii_string) # Function Parameters

        request = S7Header(socket=self.socket)
        request.send(parameters=parameters, data=b'')

        # Process Response
        response = S7Header(socket=self.socket).recv()

        result = dict()
        result['function'] = response['parameters'][0]
        if len(response['parameters']) > 1:
            result['para'] = response['parameters'][1]
            result['already_started'] = response['parameters'][1] == 0x03

        return result

    def read_szl(self, id, index):
        # Prepare first request packet
        params = bytearray()
        params.extend((0x00, 0x01, 0x12))  # Head always 0x00, 0x01, 0x12
        params.extend(struct.pack(">B", 0x04))  # Parameters Length
        params.extend(struct.pack(">B", 0x11))  # Unknown 0x11 for the first 0x12 for the next
        params.extend(struct.pack(">B", self.types_groups['grSZL']))  # Type and Group
        params.extend(struct.pack(">B", self.pdu_sub_functions['SFun_ReadSZL']))  # Subfunction
        params.extend(struct.pack(">B", 0x00))  # Sequence

        data = bytearray()
        data.extend(struct.pack(">B", 0xFF))  # return code
        data.extend(struct.pack(">B", S7.TransportSizes.Octet))  # Transport Size
        data.extend(struct.pack(">H", 4))  # Dlen
        data.extend(struct.pack(">H", id))  # Ret
        data.extend(struct.pack(">H", index))  # Ret

        request_first = S7Header(self.socket)
        request_first.send(parameters=params, data=data, pdu_type=7)

        # Interpret first request response
        response = S7Header(socket=self.socket).recv()

        # Intepret Parameters
        res_params = dict()
        res_params['head_0'] = struct.unpack(">B", response['parameters'][0:1])[0]
        res_params['head_1'] = struct.unpack(">B", response['parameters'][1:2])[0]
        res_params['head_2'] = struct.unpack(">B", response['parameters'][2:3])[0]
        res_params['plen'] = struct.unpack(">B", response['parameters'][3:4])[0]
        res_params['unknown'] = struct.unpack(">B", response['parameters'][4:5])[0]
        res_params['type_group'] = struct.unpack(">B", response['parameters'][5:6])[0]
        res_params['sub_function'] = struct.unpack(">B", response['parameters'][6:7])[0]
        res_params['sequence'] = struct.unpack(">B", response['parameters'][7:8])[0]
        if res_params['plen'] == 8:
            res_params['reserved_hi'] = struct.unpack(">B", response['parameters'][8:9])[0]
            res_params['reserved_lo'] = struct.unpack(">B", response['parameters'][9:10])[0]
            res_params['error'] = struct.unpack(">H", response['parameters'][10:12])[0]

        # Interpret Data
        res_data = dict()
        res_data['return_code'] = struct.unpack(">B", response['data'][0:1])[0]

        # If the return code is != FF there is an error in the request
        if res_data['return_code'] != 0xFF:
            return b''

        res_data['TS'] = struct.unpack(">B", response['data'][1:2])[0]
        res_data['dlen'] = struct.unpack(">H", response['data'][2:4])[0]
        res_data['ID'] = struct.unpack(">H", response['data'][4:6])[0]
        res_data['Index'] = struct.unpack(">H", response['data'][6:8])[0]

        # SZL Header
        res_data['LENTHDR'] = struct.unpack(">H", response['data'][8:10])[0]
        res_data['N_DR'] = struct.unpack(">H", response['data'][10:12])[0]

        result = bytearray()
        result.extend(response['data'][12:])

        done = res_params['reserved_hi'] == 0
        sequence_in = res_params['sequence']
        while not done:
            # Prepare first request packet
            params = bytearray()
            params.extend((0x00, 0x01, 0x12))  # Head always 0x00, 0x01, 0x12
            params.extend(struct.pack(">B", 0x08))  # Parameters Length
            params.extend(struct.pack(">B", 0x12))  # Unknown
            params.extend(struct.pack(">B", self.types_groups['grSZL']))  # Type and Group
            params.extend(struct.pack(">B", self.pdu_sub_functions['SFun_ReadSZL']))  # Subfunction
            params.extend(struct.pack(">B", sequence_in))  # Sequence
            params.extend(struct.pack(">H", 0))  # Reserved
            params.extend(struct.pack(">H", 0))  # Error Code

            data = bytearray()
            data.extend(struct.pack(">B", 0x0A))  # ret_val
            data.extend(struct.pack(">B", 0))  # Transport Size
            data.extend(struct.pack(">H", 0))  # data_len
            data.extend(struct.pack(">H", 0))  # ID (SFC51)
            data.extend(struct.pack(">H", 0))  # Index (SFC51)

            request = S7Header(self.socket)
            request.send(parameters=params, data=data, pdu_type=7)

            # Interpret next packets response params
            response = S7Header(self.socket).recv()

            # Interpret Parameters
            res_params = dict()
            res_params['head_0'] = struct.unpack(">B", response['parameters'][0:1])[0]
            res_params['head_1'] = struct.unpack(">B", response['parameters'][1:2])[0]
            res_params['head_2'] = struct.unpack(">B", response['parameters'][2:3])[0]
            res_params['plen'] = struct.unpack(">B", response['parameters'][3:4])[0]
            res_params['unknown'] = struct.unpack(">B", response['parameters'][4:5])[0]
            res_params['type_group'] = struct.unpack(">B", response['parameters'][5:6])[0]
            res_params['sub_function'] = struct.unpack(">B", response['parameters'][6:7])[0]
            res_params['sequence'] = struct.unpack(">B", response['parameters'][7:8])[0]
            if res_params['plen'] == 8:
                res_params['reserved_hi'] = struct.unpack(">B", response['parameters'][8:9])[0]
                res_params['reserved_lo'] = struct.unpack(">B", response['parameters'][9:10])[0]
                res_params['error'] = struct.unpack(">H", response['parameters'][10:12])[0]

            # Interpret Data
            res_data = dict()
            res_data['return_code'] = struct.unpack(">B", response['data'][0:1])[0]
            res_data['TS'] = struct.unpack(">B", response['data'][1:2])[0]
            res_data['dlen'] = struct.unpack(">H", response['data'][2:4])[0]
            # res_data['ID'] = struct.unpack(">H", response['data'][4:6])[0]
            # res_data['Index'] = struct.unpack(">H", response['data'][6:8])[0]

            # res_data['ListLen'] = struct.unpack(">H", response['data'][8:10])[0]
            # res_data['ListCount'] = struct.unpack(">H", response['data'][10:12])[0]
            result.extend(response['data'][4:])

            done = res_params['reserved_lo'] == 0
            sequence_in = res_params['sequence']

        return result
