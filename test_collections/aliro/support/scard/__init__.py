import platform
from ctypes import (
    POINTER,
    byref,
    c_char,
    c_char_p,
    c_uint32,
    c_ulong,
    c_void_p,
    cast,
    cdll,
    create_string_buffer,
)

from .const import SCardConstants


class SCARDCONTEXT(c_void_p):
    pass


class SCARDHANDLE(c_void_p):
    pass


class SCardError(Exception):
    pass


class SCard(SCardConstants):
    def __init__(self):
        if platform.system() == "Darwin":
            lib_name = "/System/Library/Frameworks/PCSC.framework/PCSC"
        elif platform.system() == "Linux":
            lib_name = "libpcsclite.so"
        elif platform.system() == "Windows":
            lib_name = "winscard.dll"
        else:
            raise RuntimeError(f"Unsupported platform: {platform.system()}")
        self.pcsc = cdll.LoadLibrary(lib_name)

    def __call__(self, method, *args):
        status = getattr(self.pcsc, method)(*args)
        if status != self.SCardStatus.S_SUCCESS.value:
            normalized_status = status & 0xFFFFFFFF
            try:
                raise SCardError(self.SCardStatus(normalized_status))
            except ValueError as exc:
                raise SCardError(f"PC/SC error 0x{normalized_status:08X}") from exc
        return status

    def EstablishContext(self, dwScope, pvReserved1, pvReserved2, phContext):
        return self("SCardEstablishContext", dwScope, pvReserved1, pvReserved2, phContext)

    def ReleaseContext(self, hContext):
        return self("SCardReleaseContext", hContext)

    def Connect(
        self,
        hContext,
        szReader,
        dwShareMode,
        dwPreferredProtocols,
        phCard,
        pdwActiveProtocol,
    ):
        return self(
            "SCardConnectA" if platform.system() == "Windows" else "SCardConnect",
            hContext,
            szReader,
            dwShareMode,
            dwPreferredProtocols,
            phCard,
            pdwActiveProtocol,
        )

    def Disconnect(self, hCard, dwDisposition):
        return self("SCardDisconnect", hCard, dwDisposition)

    def Status(
        self,
        hCard,
        mszReaderNames,
        pcchReaderLen,
        pdwState,
        pdwProtocol,
        pbAtr,
        pcbAtrLen,
    ):
        return self(
            "SCardStatusA" if platform.system() == "Windows" else "SCardStatus",
            hCard,
            mszReaderNames,
            pcchReaderLen,
            pdwState,
            pdwProtocol,
            pbAtr,
            pcbAtrLen,
        )

    def Transmit(
        self,
        hCard,
        pioSendPci,
        pbSendBuffer,
        cbSendLength,
        pioRecvPci,
        pbRecvBuffer,
        pcbRecvLength,
    ):
        return self(
            "SCardTransmit",
            hCard,
            pioSendPci,
            pbSendBuffer,
            cbSendLength,
            pioRecvPci,
            pbRecvBuffer,
            pcbRecvLength,
        )

    def ListReaders(self, hContext, mszGroups, mszReaders, pcchReaders):
        return self(
            "SCardListReadersA" if platform.system() == "Windows" else "SCardListReaders",
            hContext,
            mszGroups,
            mszReaders,
            pcchReaders,
        )


class SCardManager(SCard):
    def __init__(self):
        super().__init__()
        self.ctx = SCARDCONTEXT()
        self.protocol = c_ulong()
        self.EstablishContext(
            dwScope=self.Scope.USER,
            pvReserved1=0,
            pvReserved2=0,
            phContext=byref(self.ctx),
        )

    def _split_multi_string(self, ms):
        p = cast(ms, POINTER(c_char))
        return p[: len(ms)].split(b"\0")

    def _get_send_pci(self):
        if self.protocol.value == self.Protocol.T0:
            return self.pcsc.g_rgSCardT0Pci
        if self.protocol.value == self.Protocol.T1:
            return self.pcsc.g_rgSCardT1Pci
        return None

    def __iter__(self):
        pcch_readers = c_uint32()
        self.ListReaders(hContext=self.ctx, mszGroups=0, mszReaders=0, pcchReaders=byref(pcch_readers))
        s = create_string_buffer(b"\0" * pcch_readers.value)
        self.ListReaders(hContext=self.ctx, mszGroups=0, mszReaders=s, pcchReaders=byref(pcch_readers))
        for reader in self._split_multi_string(s):
            if reader:
                yield SCardReader(name=reader.decode(), manager=self)


class SCardReader(SCard):
    def __init__(self, name: str, manager: SCardManager) -> None:
        super().__init__()
        self.name = name
        self.manager = manager
        self.handle = SCARDHANDLE()

    def __enter__(self):
        self.Connect(
            hContext=self.manager.ctx,
            szReader=c_char_p(self.name.encode()),
            dwShareMode=self.ShareMode.SHARED,
            dwPreferredProtocols=self.Protocol.ANY,
            phCard=byref(self.handle),
            pdwActiveProtocol=byref(self.manager.protocol),
        )
        return self

    def disconnect(self):
        if self.handle.value is None:
            return
        self.Disconnect(hCard=self.handle, dwDisposition=self.Disposition.LEAVE_CARD)
        self.handle = SCARDHANDLE()

    def get_atr(self) -> bytes:
        reader_name_buf = create_string_buffer(self.MAX_READERNAME)
        reader_name_len = c_ulong(len(reader_name_buf))
        card_state = c_ulong()
        active_protocol = c_ulong()
        atr_buf = create_string_buffer(self.MAX_ATR_SIZE)
        atr_len = c_ulong(len(atr_buf))
        self.Status(
            hCard=self.handle,
            mszReaderNames=reader_name_buf,
            pcchReaderLen=byref(reader_name_len),
            pdwState=byref(card_state),
            pdwProtocol=byref(active_protocol),
            pbAtr=atr_buf,
            pcbAtrLen=byref(atr_len),
        )
        return atr_buf.raw[: atr_len.value]

    def transmit_apdu(self, apdu: bytes) -> bytes:
        recv_buf = create_string_buffer(self.MAX_BUFFER_SIZE_EXTENDED)
        recv_len = c_ulong(len(recv_buf))
        send_pci = self.manager._get_send_pci()
        if send_pci is None:
            raise SCardError("No active protocol available for SCardTransmit")
        self.Transmit(
            hCard=self.handle,
            pioSendPci=send_pci,
            pbSendBuffer=apdu,
            cbSendLength=len(apdu),
            pioRecvPci=0,
            pbRecvBuffer=recv_buf,
            pcbRecvLength=byref(recv_len),
        )
        return recv_buf.raw[: recv_len.value]
