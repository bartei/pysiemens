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

log = utils.get_logging(script__file__=__file__,verbose=True, level=logging.DEBUG)


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

    def __init__(self):
        super(S7Client, self).__init__()

        # Internals
        # Defaults
        self.MinPduSize = 16
        self.MinPduSizeToRequest = 240
        self.MaxPduSizeToRequest = 960

        # Properties
        self.pdu_length = 0

        # Privates
        self.LastPDUType = 0
        self.ConnectionType = self.CONNTYPE_PG
        self.Socket = None
        self.Time_ms = 0
        self.BytesRead = 0
        self.BytesWritten = 0

    def __del__(self):
        self.disconnect()

    def TCPConnect(self, address, port=102, timeout=2):
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

    def RecvPacket(self, size):
        try:
            received_data = self.Socket.recv(size)
            return received_data
        except Exception as e:
            log.error("Unable to receive data, see next message for details")
            utils.log_error(e)
            raise TcpNotConnectedError

    def SendPacket(self, Buffer, Len=0):
        try:
            if Len == 0:
                self.Socket.send(Buffer)
            else:
                self.Socket.send(Buffer[0:Len])
        except Exception as e:
            log.error("Unable to send data, see next message for details")
            utils.log_error(e)
            raise TcpNotConnectedError

    def RecvISOPacket(self, packet):
        Done = False
        Size = 0

        while not Done:
            # Get TPKT(4 bytes)
            packet.header_from_bytes(self.RecvPacket(4))
            # Now we have the length in the packet, retrieve the payload

            Size = packet.length
            # Check 0 bytes Data Packet (only TPKT+COTP = 7 bytes)
            if Size == self.IsoHSize:
                self.RecvPacket(3)  # Skip the remaining 3 bytes and Done is still false
            else:
                if Size > self._PduSizeRequested + self.IsoHSize or Size < self.MinPduSize:
                    raise IsoInvalidPduError
                else:
                    Done = True

        packet.payload_from_bytes(self.RecvPacket(Size - 4))
        return

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

    def ConnectTo(self, address, port=102, timeout=2, rack=0, slot=2, pdu_size=480):
        remote_tsap = (self.ConnectionType << 8) + (rack * 0x20) + slot
        self.TCPConnect(address=address,port=port, timeout=timeout)

        con_req = telegrams.CoptParams(self.Socket)
        result = con_req.iso_connection_request(local_tsap=0x0100, remote_tsap=remote_tsap)
        log.info("ISO Connection Request result: {}".format(result))

        negotiation = telegrams.NegotiateParams(self.Socket)
        result = negotiation.negotiate(pdu_size)
        self.pdu_length = negotiation.negotiated_pdu_length

        if not result:
            raise Exception('Failed to negotiate requested pdu length: {} != {}'.format(
                negotiation.pdu_length, negotiation.negotiated_pdu_length))

        log.info("S7 negotiated pdu length: {}".format(self.pdu_length))

    def disconnect(self):
        self.Socket.close()

    def ReadArea(self, area, db, start, num_elements, elements_type):
        read_area = telegrams.ReadArea(self.Socket, self.pdu_length)
        return read_area.read(area=area, db=db, start=start, num_elements=num_elements, elements_type=elements_type)


    def WriteArea(self, Area, DBNumber, Start, Amount, WordLen, Buffer):
        Offset = 0
        self.Time_ms = 0
        Elapsed = time.monotonic()

        # Some adjustment
        if Area == S7.Area.MK:
            WordLen = S7.DataTypes.Counter
        if Area == S7.Area.TM:
            WordLen = S7.DataTypes.Timer

        # Calc Word size
        WordSize = S7.DataSizeByte(WordLen)
        if WordSize == 0:
            raise CliInvalidWordLenError
        if WordLen == S7.DataTypes.Bit: # Only 1 bit can be transferred at time
            Amount = 1
        else:
            if (WordLen != S7.DataTypes.Counter) and (WordLen != S7.DataTypes.Timer):
                Amount = Amount * WordSize
                WordSize = 1
                WordLen = S7.DataTypes.Byte

        MaxElements = (480 - 35) // WordSize # 35 = Reply telegram header
        TotElements = Amount

        while TotElements > 0:
            NumElements = TotElements
            if NumElements > MaxElements:
                NumElements = MaxElements

            DataSize = NumElements * WordSize

            write_request_item = telegrams.WriteAreaRequestItem()
            write_request_item.DataLength = NumElements

            # Adjusts Start and word length
            if (WordLen == S7.DataTypes.Bit) or (WordLen == S7.DataTypes.Counter) or (WordLen == S7.DataTypes.Timer):
                Address = Start
                Length = DataSize
            else:
                Address = Start << 3
                Length = DataSize << 3
            write_request_item.DataLength = Length

            # Transport Size
            if WordLen == S7.DataTypes.Bit:
                write_request_item.TransportSize = self.TS_ResBit
            elif WordLen == S7.DataTypes.Counter:
                write_request_item.TransportSize = self.TS_ResOctet
            elif WordLen == S7.DataTypes.Timer:
                write_request_item.TransportSize = self.TS_ResOctet
            else:
                write_request_item.TransportSize = self.TS_ResByte

            write_request_item.data[:] = Buffer

            write_request_params = telegrams.WriteAreaRequestParameters(write_request_item)
            write_request_params.Address = Address
            write_request_params.DBNumber = DBNumber
            write_request_params.Length = NumElements
            write_request_params.Area = Area
            write_request_params.TransportSize = WordLen

            write_request = telegrams.WriteAreaRequest(write_request_params)

            s7_request_header = telegrams.S7ReqHeader(write_request)
            s7_request_header.DataLen = WordSize * NumElements + 4
            cotp_request = telegrams.COTP_DT(s7_request_header)
            packet_request = telegrams.TPKT(cotp_request)

            self.SendPacket(packet_request.to_bytes())
            print(utils.hex_log(packet_request.to_bytes()))

            write_response = telegrams.WriteAreaResponse()
            s7_response = telegrams.S7ResponseHeader23(write_response)
            cotp_response = telegrams.COTP_DT(s7_response)
            packet_response = telegrams.TPKT(cotp_response)

            self.RecvISOPacket(packet_response)
            print(utils.hex_log(packet_response.to_bytes()))


            # if packet_response.length == 22:
            #     if s7_response.  self.PDU[21] != 0xFF:
            #         self.__cpu_error(self.PDU[21])
            # else:
            #     raise IsoInvalidPduError

            Offset += DataSize
            TotElements -= NumElements
            Start += NumElements * WordSize

        self.BytesWritten = Offset
        self.Time_ms = time.monotonic() - Elapsed

    def ReadMultiVars(self, Items, ItemsCount):
        S7Item = bytearray(12)
        S7ItemRead = bytearray(1024)

        self.Time_ms = 0
        Elapsed = time.monotonic()

        # Checks items
        if ItemsCount > self.MaxVars:
            raise CliTooManyItemsError

        # Fills Header
        self.PDU[0:len(s7telegrams.S7_MRD_HEADER)] = s7telegrams.S7_MRD_HEADER[:]
        S7.SetWordAt(self.PDU, 13, (ItemsCount * len(S7Item) + 2))
        self.PDU[18] = ItemsCount

        # Fills the Items
        Offset = 19
        for c in range(0, ItemsCount):
            S7Item[0:len(s7telegrams.S7_MRD_ITEM)] = s7telegrams.S7_MRD_ITEM[0:len(s7telegrams.S7_MRD_ITEM)]
            S7Item[3] = Items[c].WordLen

            S7.SetWordAt(S7Item, 4, Items[c].Amount)

            if Items[c].Area == const.DB:
                S7.SetWordAt(S7Item, 6, Items[c].DBNumber)
            S7Item[8] = Items[c].Area

            # Address into the PLC
            Address = Items[c].Start
            S7.SetByteAt(S7Item, 11, Address & 0x0FF)

            Address = Address >> 8
            S7.SetByteAt(S7Item, 10, Address & 0x0FF)

            Address = Address >> 8
            S7.SetByteAt(S7Item, 9, Address & 0x0FF)

            self.PDU[Offset:Offset+len(S7Item)] = S7Item[0:len(S7Item)]
            Offset += len(S7Item)

        if Offset > self.PduLength:
            raise CliSizeOverPduError

        S7.SetWordAt(self.PDU, 2, Offset)  # Whole size
        self.SendPacket(self.PDU, Offset)

        # Get Answer
        Length = self.RecvISOPacket()

        # Check ISO Length
        if Length < 22:
            raise IsoInvalidPduError

        # Check Global Operation Result
        self.__cpu_error(S7.GetWordAt(self.PDU, 17))

        # Get true ItemsCount
        ItemsRead = S7.GetByteAt(self.PDU, 20)
        if (ItemsRead != ItemsCount) or (ItemsRead > self.MaxVars):
            raise CliInvalidPlcAnswerError

        # Get Data
        Offset = 21
        for c in range(0, ItemsCount):
            # Get the Item
            S7ItemRead[0:Length-Offset] = self.PDU[Offset:Length]

            if S7ItemRead[0] == 0xff:
                ItemSize = S7.GetWordAt(S7ItemRead, 2)
                if (S7ItemRead[1] != self.TS_ResOctet) and (S7ItemRead[1] != self.TS_ResReal) and (S7ItemRead[1] != self.TS_ResBit):
                    ItemSize = ItemSize >> 3

                Items[c].pData[:] = S7ItemRead[4:4+ItemSize]
                Items[c].Result = 0

                if ItemSize % 2 != 0:
                    ItemSize += 1 # Odd size are rounded
                Offset = Offset + 4 + ItemSize
            else:
                Items[c].Result = self.__cpu_error(S7ItemRead[0])
                Offset += 4  # Skip the Item header
        self.Time_ms = time.monotonic() - Elapsed

    def DBRead(self, DBNumber, Start, Size):
        return self.ReadArea(S7.Area.DB, DBNumber, Start, Size, S7.DataTypes.Byte)

    def DBWrite(self, DBNumber, Start, Size, Buffer):
        return self.WriteArea(S7.Area.DB, DBNumber, Start, Size, S7.DataTypes.Byte, Buffer)

    def MBRead(self, Start, Size, Buffer):
        return self.ReadArea(S7.Area.MK, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def MBWrite(self, Start, Size, Buffer):
        return self.WriteArea(S7.Area.MK, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def EBRead(self, Start, Size, Buffer):
        return self.ReadArea(S7.Area.PE, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def EBWrite(self, Start, Size, Buffer):
        return self.WriteArea(S7.Area.PE, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def ABRead(self, Start, Size, Buffer):
        return self.ReadArea(S7.Area.PA, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def ABWrite(self, Start, Size, Buffer):
        return self.WriteArea(S7.Area.PA, 0, Start, Size, S7.DataTypes.Byte, Buffer)

    def TMRead(self, Start, Amount, Buffer):
        sBuffer = bytearray(Amount * 2)
        self.ReadArea(S7.Area.TM, 0, Start, Amount, S7.DataTypes.Timer, sBuffer)
        for c in range(0, Amount):
            Buffer[c] = ((sBuffer[c * 2 + 1] << 8) + (sBuffer[c * 2]))

    def TMWrite(self, Start, Amount, Buffer):
        sBuffer = bytearray(Amount * 2)
        for c in range(0, Amount):
            sBuffer[c * 2 + 1] = ((Buffer[c] & 0xFF00) >> 8)
            sBuffer[c * 2] = (Buffer[c] & 0x00FF)

        self.WriteArea(S7.Area.TM, 0, Start, Amount, S7.DataTypes.Timer, sBuffer)

    def CTRead(self, Start, Amount, Buffer):
        sBuffer = bytearray(Amount * 2)
        self.ReadArea(S7.Area.CT, 0, Start, Amount, S7.DataTypes.Counter, sBuffer)
        for c in range(0, Amount):
            Buffer[c] = ((sBuffer[c * 2 + 1] << 8) + (sBuffer[c * 2]))

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

    def GetAgBlockInfo(self, BlockType, BlockNum):
        self.Time_ms = 0
        Elapsed = time.monotonic()
        result = {}

        S7_BI = bytearray()
        S7_BI[:] = s7telegrams.S7_BI
        S7.SetByteAt(S7_BI, 30, BlockType)

        # Block Number
        S7.SetByteAt(S7_BI, 31, BlockNum // 10000 + 0x30)
        S7.SetByteAt(S7_BI, 32, BlockNum // 1000 + 0x30)
        S7.SetByteAt(S7_BI, 33, BlockNum // 100 + 0x30)
        S7.SetByteAt(S7_BI, 34, BlockNum // 10 + 0x30)
        S7.SetByteAt(S7_BI, 35, BlockNum // 1 + 0x30)

        self.SendPacket(S7_BI)

        Length = self.RecvISOPacket()
        if Length > 32:  # the minimum expected
            Result = S7.GetWordAt(self.PDU, 27)
            if Result == 0:
                result['BlkFlags'] = self.PDU[42]
                result['BlkLang'] = self.PDU[43]
                result['BlkType'] = self.PDU[44]
                result['BlkNumber'] = S7.GetWordAt(self.PDU, 45)
                result['LoadSize'] = S7.GetDIntAt(self.PDU, 47)
                result['CodeDate'] = self.SiemensTimestamp(EncodedDate=S7.GetWordAt(self.PDU, 59))
                result['IntfDate'] = self.SiemensTimestamp(EncodedDate=S7.GetWordAt(self.PDU, 65))
                result['SBBLength'] = S7.GetWordAt(self.PDU, 67)
                result['LocalData'] = S7.GetWordAt(self.PDU, 71)
                result['MC7Size'] = S7.GetWordAt(self.PDU, 73)
                result['Author'] = S7.GetCharsAt(self.PDU, 75, 8)
                result['Family'] = S7.GetCharsAt(self.PDU, 83, 8)
                result['Header'] = S7.GetCharsAt(self.PDU, 91, 8)
                result['Version'] = self.PDU[99]
                result['CheckSum'] = S7.GetWordAt(self.PDU, 101)
            else:
                self.__cpu_error(Result)
        else:
            raise IsoInvalidPduError

        self.Time_ms = time.monotonic() - Elapsed

        return result

    def ReadSZL(self, ID, Index, SZL : S7SZL):
        SZL.Data = bytearray()
        Done = False
        First = True
        Seq_in = 0x00
        Seq_out = 0x0000
        self.Time_ms = 0
        Elapsed = time.monotonic()
        SZL.Header.LENTHDR = 0

        S7_SZL_FIRST = bytearray()
        S7_SZL_FIRST[:] = s7telegrams.S7_SZL_FIRST

        S7_SZL_NEXT = bytearray()
        S7_SZL_NEXT[:] = s7telegrams.S7_SZL_NEXT

        while not Done:
            if First:
                Seq_out += 1
                S7.SetWordAt(S7_SZL_FIRST, 11, Seq_out)
                S7.SetWordAt(S7_SZL_FIRST, 29, ID)
                S7.SetWordAt(S7_SZL_FIRST, 31, Index)
                self.SendPacket(S7_SZL_FIRST)
            else:
                Seq_out += 1
                S7.SetWordAt(S7_SZL_NEXT, 11, ++Seq_out)
                self.PDU[24] = Seq_in
                self.SendPacket(S7_SZL_NEXT)

            Length = self.RecvISOPacket()
            if First:
                if Length > 32:  # the minimum expected
                    if (S7.GetWordAt(self.PDU, 27) == 0) and (self.PDU[29] == 0xFF):
                        # Gets Amount of this slice
                        DataSZL = S7.GetWordAt(self.PDU, 31) - 8  # Skips extra params (ID, Index ...)
                        Done = self.PDU[26] == 0x00
                        Seq_in = self.PDU[24]  # Slice sequence
                        SZL.Header.LENTHDR = S7.GetWordAt(self.PDU, 37)
                        SZL.Header.N_DR = S7.GetWordAt(self.PDU, 39)
                        SZL.Data.extend(self.PDU[41:41+DataSZL])
                        SZL.Header.LENTHDR += SZL.Header.LENTHDR
                    else:
                        raise CliInvalidPlcAnswerError
                else:
                    raise IsoInvalidPduError
            else:
                if Length > 32:  # the minimum expected
                    if (S7.GetWordAt(self.PDU, 27) == 0) and (self.PDU[29] == 0xFF):
                        # Gets Amount of this slice
                        DataSZL = S7.GetWordAt(self.PDU, 31)
                        Done = self.PDU[26] == 0x00
                        Seq_in = self.PDU[24]  # Slice sequence
                        SZL.Data.extend(self.PDU[37:37+DataSZL])
                        SZL.Header.LENTHDR += SZL.Header.LENTHDR
                    else:
                        raise CliInvalidPlcAnswerError
                else:
                    raise IsoInvalidPduError

            First = False

        self.Time_ms = time.monotonic() - Elapsed

    def GetOrderCode(self):
        SZL = S7SZL()
        Elapsed = time.monotonic()
        self.ReadSZL(0x0011, 0x000, SZL)

        Info = dict()
        Info['Code'] = S7.GetCharsAt(SZL.Data, 2, 20)
        Info['V1'] = S7.GetByteAt(SZL.Data, len(SZL.Data)-3)
        Info['V2'] = S7.GetByteAt(SZL.Data, len(SZL.Data)-2)
        Info['V3'] = S7.GetByteAt(SZL.Data, len(SZL.Data)-1)
        self.Time_ms = time.monotonic() - Elapsed
        return Info

    def GetCpuInfo(self):
        SZL = S7SZL()
        Elapsed = time.monotonic()
        self.ReadSZL(0x001C, 0x000, SZL)

        Info = dict()
        Info['ModuleTypeName'] = S7.GetCharsAt(SZL.Data, 172, 32)
        Info['SerialNumber'] = S7.GetCharsAt(SZL.Data, 138, 24)
        Info['ASName'] = S7.GetCharsAt(SZL.Data, 2, 24)
        Info['Copyright'] = S7.GetCharsAt(SZL.Data, 104, 26)
        Info['ModuleName'] = S7.GetCharsAt(SZL.Data, 36, 24)

        self.Time_ms = time.monotonic() - Elapsed
        return Info

    def GetCpInfo(self):
        SZL = S7SZL()
        Elapsed = time.monotonic()
        self.ReadSZL(0x0131, 0x001, SZL)

        Info = dict()
        Info['MaxPduLength'] = S7.GetIntAt(SZL.Data, 2)
        Info['MaxConnections'] = S7.GetIntAt(SZL.Data, 4)
        Info['MaxMpiRate'] = S7.GetDIntAt(SZL.Data, 6)
        Info['MaxBusRate'] = S7.GetDIntAt(SZL.Data, 10)

        self.Time_ms = time.monotonic() - Elapsed
        return Info

    def PlcHotStart(self):
        Elapsed = time.monotonic()

        self.SendPacket(s7telegrams.S7_HOT_START)
        Length = self.RecvISOPacket()

        if Length <= 18:  # 18 is the minimum expected
            raise IsoInvalidPduError
        if self.PDU[19] != s7telegrams.pduStart:
            raise CliCannotStartPlcError
        if self.PDU[20] == s7telegrams.pduAlreadyStarted:
            raise CliAlreadyRunError

        self.Time_ms = time.monotonic() - Elapsed

    def PlcStop(self):
        Elapsed = time.monotonic()

        self.SendPacket(s7telegrams.S7_STOP)
        Length = self.RecvISOPacket()

        if Length <= 18:  # 18 is the minimum expected
            raise IsoInvalidPduError
        if self.PDU[19] != s7telegrams.pduStop:
            raise CliCannotStopPlcError
        if self.PDU[20] == s7telegrams.pduAlreadyStopped:
            raise CliAlreadyStopError

        self.Time_ms = time.monotonic() - Elapsed

    def PlcColdStart(self):
        Elapsed = time.monotonic()

        self.SendPacket(s7telegrams.S7_COLD_START)
        Length = self.RecvISOPacket()

        if Length <= 18:  # 18 is the minimum expected
            raise IsoInvalidPduError
        if self.PDU[19] != s7telegrams.pduStart:
            raise CliCannotStartPlcError
        if self.PDU[20] == s7telegrams.pduAlreadyStarted:
            raise CliAlreadyRunError

        self.Time_ms = time.monotonic() - Elapsed

    def GetPlcStatus(self):
        Elapsed = time.monotonic()
        self.SendPacket(s7telegrams.S7_GET_STAT)
        Length = self.RecvISOPacket()

        if Length <= 30:  # the minimum expected
            raise IsoInvalidPduError

        Result = S7.GetWordAt(self.PDU, 27)
        if Result != 0:
            self.__cpu_error(Result)

        Status = self.PDU[44]

        self.Time_ms = time.monotonic() - Elapsed
        return next((item for item in const.S7PlcStatuses if item['Code'] == Status), None)
