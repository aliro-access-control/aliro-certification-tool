from enum import Enum
from ctypes import Structure, c_char_p, c_void_p, c_uint32, c_char


class SCardConstants:
    MAX_BUFFER_SIZE = 264
    MAX_BUFFER_SIZE_EXTENDED = 4 + 3 + (1 << 16) + 3
    MAX_ATR_SIZE = 36
    MAX_READERNAME = 256

    class SCARD_READERSTATE(Structure):
        _fields_ = [
            ("szReader", c_char_p),
            ("pvUserData", c_void_p),
            ("dwCurrentState", c_uint32),
            ("dwEventState", c_uint32),
            ("cbAtr", c_uint32),
            ("rgbAtr", c_char * 36),
        ]

    class SCardStatus(Enum):
        S_SUCCESS = 0x00000000
        E_NO_READERS_AVAILABLE = 0x8010002E

    class Scope:
        USER = 0x0000
        TERMINAL = 0x0001
        SYSTEM = 0x0002

    class Protocol:
        UNDEFINED = 0x0000
        UNSET = UNDEFINED
        T0 = 0x0001
        T1 = 0x0002
        RAW = 0x0004
        T15 = 0x0008
        ANY = T0 | T1

    class ShareMode:
        EXCLUSIVE = 0x0001
        SHARED = 0x0002
        DIRECT = 0x0003

    class Disposition:
        LEAVE_CARD = 0x0000
        RESET_CARD = 0x0001
        UNPOWER_CARD = 0x0002
        EJECT_CARD = 0x0003
