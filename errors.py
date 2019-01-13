class TcpSocketCreationError(Exception):
    pass

class TcpConnectionTimeoutError(Exception):
    pass

class TcpConnectionFailedError(Exception):
    pass

class TcpReceiveTimeoutError(Exception):
    pass

class TcpDataReceiveError(Exception):
    pass

class TcpSendTimeoutError(Exception):
    pass

class TcpDataSendError(Exception):
    pass

class TcpConnectionResetError(Exception):
    pass

class TcpNotConnectedError(Exception):
    pass

class TcpUnreachableHostError(Exception):
    pass


class IsoConnectError(Exception):
    pass

class IsoInvalidPduError(Exception):
    pass

class IsoInvalidDataSizeError(Exception):
    pass


class CliNegotiatingPduError(Exception):
    pass

class CliInvalidParamsError(Exception):
    pass

class CliJobPendingError(Exception):
    pass

class CliTooManyItemsError(Exception):
    pass

class CliInvalidWordLenError(Exception):
    pass

class CliPartialDataWrittenError(Exception):
    pass

class CliSizeOverPduError(Exception):
    pass

class CliInvalidPlcAnswerError(Exception):
    pass

class CliAddressOutOfRangeError(Exception):
    pass

class CliInvalidTransportSizeError(Exception):
    pass

class CliWriteDataSizeMismatchError(Exception):
    pass

class CliItemNotAvailableError(Exception):
    pass

class CliInvalidValueError(Exception):
    pass

class CliCannotStartPlcError(Exception):
    pass

class CliAlreadyRunError(Exception):
    pass

class CliCannotStopPlcError(Exception):
    pass

class CliCannotCopyRamToRomError(Exception):
    pass

class CliCannotCompressError(Exception):
    pass

class CliAlreadyStopError(Exception):
    pass

class CliFunNotAvailableError(Exception):
    pass

class CliUploadSequenceFailedError(Exception):
    pass

class CliInvalidDataSizeRecvdError(Exception):
    pass

class CliInvalidBlockTypeError(Exception):
    pass

class CliInvalidBlockNumberError(Exception):
    pass

class CliInvalidBlockSizeError(Exception):
    pass

class CliNeedPasswordError(Exception):
    pass

class CliInvalidPasswordError(Exception):
    pass

class CliNoPasswordToSetOrClearError(Exception):
    pass

class CliJobTimeoutError(Exception):
    pass

class CliPartialDataReadError(Exception):
    pass

class CliBufferTooSmallError(Exception):
    pass

class CliFunctionRefusedError(Exception):
    pass

class CliDestroyingError(Exception):
    pass

class CliInvalidParamNumberError(Exception):
    pass

class CliCannotChangeParamError(Exception):
    pass

class CliFunctionNotImplementedError(Exception):
    pass