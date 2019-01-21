import siemens
import S7
import datetime
import utils
import logging
log = utils.get_logging(script__file__=__file__,verbose=True, level=logging.INFO)

client = siemens.S7Client(address='10.1.2.69', port=102, rack=0, slot=2, pdu_length=120)

Buffer = client.DBRead(1, 0, 90)
print(S7.GetDIntAt(Buffer, 2))
print(S7.GetTODAt(Buffer, 76))
print(S7.GetDateAt(Buffer, 70))
print(S7.GetDateTimeAt(Buffer, 58))

S7.SetIntAt(Buffer, 0, 100)
S7.SetDIntAt(Buffer, 2, 101)
S7.SetIntAt(Buffer, 6, 102)
S7.SetIntAt(Buffer, 8, 103)
S7.SetIntAt(Buffer, 10, 104)
S7.SetIntAt(Buffer, 12, 105)
S7.SetIntAt(Buffer, 14, 0)
S7.SetIntAt(Buffer, 16, 0)
S7.SetIntAt(Buffer, 18, 0)
S7.SetIntAt(Buffer, 20, 0)
S7.SetFloatAt(Buffer, 66, 123.456789)

S7.SetDateTimeAt(Buffer, 58, datetime.datetime.now())
S7.SetDateAt(Buffer, 70, datetime.date(year=2020, month=12, day=15))
Buffer[80:85] = b'MERDA'
result = client.DBWrite(1, 0, len(Buffer), Buffer)
print("Result of write at address 2")
print(result)

# result = client.PlcStop()
# log.info("Plc Stop Result: {}".format(result))
# print(client.GetPlcStatus())
#
# result = client.PlcHotStart()
# log.info("Plc Start Result: {}".format(result))
# print(client.GetPlcStatus())
#
# result = client.PlcStop()
# log.info("Plc Stop Result: {}".format(result))
# print(client.GetPlcStatus())
#
# result = client.PlcColdStart()
# log.info("Plc Start Result: {}".format(result))
# print(client.GetPlcStatus())


print(client.GetCpuInfo())
print(client.GetModuleId())
print(client.GetOrderCode())
print(client.GetCpInfo())
print(client.GetPlcStatus())
# tosend = bytearray(1)
# S7.SetBitAt(tosend, 0, 0, False)
# client.DBWrite(1, 30, len(tosend), tosend)
# tosend = bytearray(4)
# S7.SetFloatAt(tosend, 0, 12342342423421.123)
# client.DBWrite(1, 66, 4, tosend)

# infos = client.GetAgBlockInfo(BlockType=client.Block_DB, BlockNum=1)
# print(infos)
#
# order_code = client.GetOrderCode()
# print(order_code)
#
# cpu_info = client.GetCpuInfo()
# print(cpu_info)
#
# cp_info = client.GetCpInfo()
# print(cp_info)

# client.PlcStop()
# print("Stopped")
# client.PlcColdStart()
# print("HotStart")

# print(client.GetPlcStatus())