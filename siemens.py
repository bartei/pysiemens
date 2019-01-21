import struct
import utils
import const
import socket
import S7
import s7telegrams
import time
import datetime
import logging
import telegrams

from errors import *

log = logging.getLogger()

class S7DataItem(object):
    def __init__(self):
        super(S7DataItem, self).__init__()
        self.area = 0
        self.word_len = 0
        self.result = 0
        self.db_number = 0
        self.start = 0
        self.amount = 0
        self.data = bytearray()


class S7OrderCode(object):
    def __init__(self):
        super(S7OrderCode, self).__init__()
        self.code = ""
        self.v1 = 0
        self.v2 = 0
        self.v3 = 0


class S7CpuInfo(object):
    def __init__(self):
        super(S7CpuInfo, self).__init__()
        self.module_type_name = ""
        self.serial_number = ""
        self.a_s_name = ""
        self.copyright = ""
        self.module_name = ""


class S7CpInfo(object):
    def __init__(self):
        super(S7CpInfo, self).__init__()
        self.max_pdu_length = 0
        self.max_connections = 0
        self.max_mpi_rate = 0
        self.max_bus_rate = 0


class S7BlocksList(object):
    def __init__(self):
        super(S7BlocksList, self).__init__()
        self.ob_count = 0
        self.fb_count = 0
        self.fc_Count = 0
        self.sfb_count = 0
        self.sfc_Count = 0
        self.db_count = 0
        self.sdb_count = 0


class SZL_HEADER(object):
    def __init__(self):
        super(SZL_HEADER, self).__init__()
        self.LENTHDR = 0
        self.N_DR = 0

    def to_bytes(self):
        try:
            result = struct.pack("HH", self.LENTHDR, self.N_DR)
            return result
        except Exception as e:
            log.error("Unable to pack the values given")
            utils.log_error(e)
            return None


class S7SZL(object):
    def __init__(self):
        self.Header = SZL_HEADER()
        self.Data = bytearray()

    def to_bytes(self):
        try:
            result = self.Header.to_bytes() + self.Data
            return result
        except Exception as e:
            log.error("Unable to packe the values given")
            utils.log_error(e)
            return None


class S7SZLList(object):
    def __init__(self):
        super(S7SZLList, self).__init__()
        self.Header = SZL_HEADER()
        self.Data = bytearray(0x2000 - 2)


class S7Protection(object):
    def __init__(self):
        super(S7Protection, self).__init__()
        self.sch_schal = 0
        self.sch_par = 0
        self.sch_rel = 0
        self.bart_sch = 0
        self.anl_sch = 0


class S7Client(object):
    # Block type
    Block_OB = 0x38
    Block_DB = 0x41
    Block_SDB = 0x42
    Block_FC = 0x43
    Block_SFC = 0x44
    Block_FB = 0x45
    Block_SFB = 0x46

    # Sub Block Type
    SubBlk_OB = 0x08
    SubBlk_DB = 0x0A
    SubBlk_SDB = 0x0B
    SubBlk_FC = 0x0C
    SubBlk_SFC = 0x0D
    SubBlk_FB = 0x0E
    SubBlk_SFB = 0x0F

    # Block languages
    BlockLangAWL = 0x01
    BlockLangKOP = 0x02
    BlockLangFUP = 0x03
    BlockLangSCL = 0x04
    BlockLangDB = 0x05
    BlockLangGRAPH = 0x06

    # Max number of vars (multirea d /write)
    MaxVars = 20

    # Result transport size
    TS_ResBit = 0x03
    TS_ResByte = 0x04
    TS_ResInt = 0x05
    TS_ResReal = 0x07
    TS_ResOctet = 0x09

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

    # Client Connection Type
    CONNTYPE_PG = 0x01  # Connect to the PLC as a PG
    CONNTYPE_OP = 0x02  # Connect to the PLC as an OP
    CONNTYPE_BASIC = 0x03  # Basic connection

    # Socket
    DefaultTimeout = 2.0

    def __init__(self, address, port=102, timeout=2, rack=0, slot=2, pdu_length=480):
        super(S7Client, self).__init__()

        # Internals
        # Defaults
        self.MinPduSize = 16
        self.MinPduSizeToRequest = 240
        self.MaxPduSizeToRequest = 960

        # Privates
        try:
            self.Socket = socket.socket()
            self.Socket.settimeout(timeout)
            self.Socket.connect((address, port))
        except socket.timeout:
            raise TcpConnectionTimeoutError

        except Exception as e:
            log.error("TCP Connection Failed IP: {}, Port: {}".format(address, port))
            utils.log_error(e)
            raise TcpConnectionFailedError

        remote_tsap = (self.CONNTYPE_PG << 8) + (rack * 0x20) + slot

        con_req = telegrams.CoptParams(self.Socket)
        result = con_req.iso_connection_request(local_tsap=0x0100, remote_tsap=remote_tsap)
        log.info("ISO Connection Request result: {}".format(result))

        self.functions = telegrams.S7Functions(socket=self.Socket)
        result = self.functions.negotiate(pdu_length=pdu_length)

        if not result:
            raise Exception('Failed to negotiate requested pdu length: {} != {}'.format(
                self.functions.pdu_length, pdu_length))

        log.info("S7 negotiated pdu length: {}".format(pdu_length))


    def __del__(self):
        self.disconnect()

    def __cpu_error(self, Error):
        if Error == 0:
            return 0
        elif Error == self.Code7AddressOutOfRange:
            raise CliAddressOutOfRangeError

        elif Error == self.Code7InvalidTransportSize:
            raise CliInvalidTransportSizeError
        elif Error == self.Code7WriteDataSizeMismatch:
            raise CliWriteDataSizeMismatchError
        elif Error == self.Code7ResItemNotAvailable:
            raise CliItemNotAvailableError
        elif Error == self.Code7ResItemNotAvailable1:
            raise CliItemNotAvailableError
        elif Error == self.Code7DataOverPDU:
            raise CliSizeOverPduError
        elif Error == self.Code7InvalidValue:
            raise CliInvalidValueError
        elif Error == self.Code7FunNotAvailable:
            raise CliFunNotAvailableError
        elif Error == self.Code7NeedPassword:
            raise CliNeedPasswordError
        elif Error == self.Code7InvalidPassword:
            raise CliInvalidPasswordError
        elif Error == self.Code7NoPasswordToSet:
            raise CliNoPasswordToSetOrClearError
        elif Error == self.Code7NoPasswordToClear:
            raise CliNoPasswordToSetOrClearError
        else:
            raise CliFunctionRefusedError

    def disconnect(self):
        self.Socket.close()

    def ReadArea(self, area, db, start, num_elements, elements_type):
        result = self.functions.read_raw(area=area, db=db, offset=start, elements_count=num_elements,
                                    elements_type=elements_type)
        return result.get("data", bytearray(0))


    def WriteArea(self, Area, DBNumber, Start, Amount, WordLen, Buffer):
        return self.functions.write_raw(area=Area, db=DBNumber, start=Start,num_elements=Amount,elements_type=WordLen,
                                   data=Buffer)

    def DBRead(self, DBNumber, Start, Size):
        return self.ReadArea(S7.Area.DB, DBNumber, Start, Size, S7.DataTypes.Byte)

    def DBWrite(self, DBNumber, Start, Size, Buffer):
        return self.WriteArea(S7.Area.DB, DBNumber, Start, Size, S7.DataTypes.Byte, Buffer)

    def MBRead(self, Start, Size):
        return self.ReadArea(S7.Area.MK, 0, Start, Size, S7.DataTypes.Byte)

    def MBWrite(self, Start, Size, Buffer):
        return self.WriteArea(S7.Area.MK, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def EBRead(self, Start, Size):
        return self.ReadArea(S7.Area.PE, 0, Start, Size, S7.DataTypes.Byte)

    def EBWrite(self, Start, Size, Buffer):
        return self.WriteArea(S7.Area.PE, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def ABRead(self, Start, Size):
        return self.ReadArea(S7.Area.PA, 0, Start, Size, S7.DataTypes.Byte)

    def ABWrite(self, Start, Size, Buffer):
        return self.WriteArea(S7.Area.PA, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def TMRead(self, Start, Amount):
        raw_buffer =  self.ReadArea(S7.Area.TM, 0, Start, Amount, S7.DataTypes.Timer)
        for c in range(0, Amount):
            buffer[c] = ((raw_buffer[c * 2 + 1] << 8) + (raw_buffer[c * 2]))

        return buffer

    def TMWrite(self, Start, Amount, Buffer):
        sBuffer = bytearray(Amount * 2)
        for c in range(0, Amount):
            sBuffer[c * 2 + 1] = ((Buffer[c] & 0xFF00) >> 8)
            sBuffer[c * 2] = (Buffer[c] & 0x00FF)

        self.WriteArea(S7.Area.TM, 0, Start, Amount, S7.DataTypes.Timer, sBuffer)

    def CTRead(self, Start, Amount):
        sBuffer = self.ReadArea(S7.Area.CT, 0, Start, Amount, S7.DataTypes.Counter)
        for c in range(0, Amount):
            Buffer[c] = ((sBuffer[c * 2 + 1] << 8) + (sBuffer[c * 2]))

        return Buffer

    def CTWrite(self, Start, Amount, Buffer):
        sBuffer = bytearray(Amount * 2)
        for c in range(0, Amount):
            sBuffer[c * 2 + 1] = ((Buffer[c] & 0xFF00)>>8)
            sBuffer[c * 2]= (Buffer[c] & 0x00FF)

        self.WriteArea(S7.Area.CT, 0, Start, Amount, S7.DataTypes.Counter, sBuffer)

    @staticmethod
    def SiemensTimestamp(EncodedDate):
        DT = datetime.datetime(year=1984, month=1, day=1, hour=0, minute=0, second=0)
        Delta = datetime.timedelta(days=EncodedDate)
        DT = DT + Delta
        return DT.isoformat()

    def PlcHotStart(self):
        result = self.functions.plc_hot_start()
        return result

    def PlcStop(self):
        result = self.functions.plc_stop()
        return result

    def PlcColdStart(self):
        result = self.functions.plc_cold_start()
        return result

    def GetPlcStatus(self):
        result = self.functions.read_szl(id=0x0424, index=0x0000)

        Info = dict()
        Info['StatusCode'] = result[3]
        Info['Run'] = Info['StatusCode'] == 0x08
        Info['Stop'] = Info['StatusCode'] != 0x08

        return Info

    def GetOrderCode(self):
        result = self.functions.read_szl(id=0x0011, index=0x0000)

        Info = dict()
        Info['Code'] = S7.GetCharsAt(result, 2, 20)
        Info['V1'] = S7.GetByteAt(result, len(result)-3)
        Info['V2'] = S7.GetByteAt(result, len(result)-2)
        Info['V3'] = S7.GetByteAt(result, len(result)-1)
        return Info

    def GetCpuInfo(self):
        result = self.functions.read_szl(id=0x001C, index=0x0000)

        Info = dict()

        index = 0
        while index < len(result):
            element = result[index:index+34]
            element_identifier = struct.unpack(">H", element[0:2])[0]

            # PLC Name
            if element_identifier == 1:
                Info['PlcName'] = element[2:2+24].decode("utf-8").replace('\x00', '')

            # Name
            if element_identifier == 2:
                Info['Name'] = element[2:2+24].decode("utf-8").replace('\x00', '')

            # Plant
            if element_identifier == 3:
                Info['Plant'] = element[2:2+32].decode("utf-8").replace('\x00', '')

            # Copyright
            if element_identifier == 4:
                Info['Copyright'] = element[2:2+26].decode("utf-8").replace('\x00', '')

            # Serial Number
            if element_identifier == 5:
                Info['SerialNumber'] = element[2:2+24].decode("utf-8").replace('\x00', '')

            # Module Type Name
            if element_identifier == 7:
                Info['ModuleTypeName'] = element[2:2+32].decode("utf-8").replace('\x00', '')

            # MMC Serial Number
            if element_identifier == 8:
                Info['MmcSerialNumber'] = element[2:2+32].decode("utf-8").replace('\x00', '')

            # OEM ID
            if element_identifier == 0xA:
                Info['OemId'] = element[2:2+26].decode("utf-8").replace('\x00', '')

            # Location Id
            if element_identifier == 0xA:
                Info['LocationId'] = element[2:2+32].decode("utf-8").replace('\x00', '')

            index += 34

        return Info

    def GetModuleId(self):
        result = self.functions.read_szl(id=0x0111, index=0x0001) # Module

        Info = dict()
        Info['Index'] = struct.unpack(">H", result[0:2])[0]
        Info['MIFB'] = result[2:22].decode("utf-8")
        Info['BGTyp'] = struct.unpack(">H", result[22:24])[0]
        Info['AusBg1'] = struct.unpack(">H", result[24:26])[0]
        Info['AusBg2'] = struct.unpack(">H", result[26:28])[0]

        return Info

    def GetCpInfo(self):
        result = self.functions.read_szl(id=0x0131, index=0x0001)

        Info = dict()
        Info['MaxPduLength'] = struct.unpack(">H", result[2:4])[0]
        Info['MaxConnections'] = struct.unpack(">H", result[4:6])[0]
        Info['MaxMpiRate'] = struct.unpack(">H", result[6:8])[0]
        Info['MaxBusRate'] = struct.unpack(">H", result[10:12])[0]

        return Info
