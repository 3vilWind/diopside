MAX_BIT = 1 << 63


def encode_error(status):
    return MAX_BIT | status


EFI_SUCCESS = 0

EFI_LOAD_ERROR = encode_error(1)
EFI_INVALID_PARAMETER = encode_error(2)
EFI_UNSUPPORTED = encode_error(3)
EFI_BAD_BUFFER_SIZE = encode_error(4)
EFI_BUFFER_TOO_SMALL = encode_error(5)
EFI_NOT_READY = encode_error(6)
EFI_DEVICE_ERROR = encode_error(7)
EFI_WRITE_PROTECTED = encode_error(8)
EFI_OUT_OF_RESOURCES = encode_error(9)
EFI_VOLUME_CORRUPTED = encode_error(10)
EFI_VOLUME_FULL = encode_error(11)
EFI_NO_MEDIA = encode_error(12)
EFI_MEDIA_CHANGED = encode_error(13)
EFI_NOT_FOUND = encode_error(14)
EFI_ACCESS_DENIED = encode_error(15)
EFI_NO_RESPONSE = encode_error(16)
EFI_NO_MAPPING = encode_error(17)
EFI_TIMEOUT = encode_error(18)
EFI_NOT_STARTED = encode_error(19)
EFI_ALREADY_STARTED = encode_error(20)
EFI_ABORTED = encode_error(21)
EFI_ICMP_ERROR = encode_error(22)
EFI_TFTP_ERROR = encode_error(23)
EFI_PROTOCOL_ERROR = encode_error(24)
EFI_INCOMPATIBLE_VERSION = encode_error(25)
EFI_SECURITY_VIOLATION = encode_error(26)
EFI_CRC_ERROR = encode_error(27)
EFI_END_OF_MEDIA = encode_error(28)
EFI_END_OF_FILE = encode_error(31)
EFI_INVALID_LANGUAGE = encode_error(32)
EFI_COMPROMISED_DATA = encode_error(33)
EFI_HTTP_ERROR = encode_error(35)
