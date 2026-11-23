#
# Copyright (c) 2026 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import socket
import time
from typing import Literal

from aliro_actuator import Global
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.errors import InvalidModeError, NoDataReceivedError

from .scard import SCardManager

NFCCardBackend = Literal["simulator", "pcsc"]
MAX_SHORT_APDU_LENGTH = 255


def xor_checksum(data: bytes) -> int:
    checksum = 0
    for value in data:
        checksum ^= value
    return checksum


class SimulatorCardBackend:
    def __init__(self, host: str = "localhost", port: int = 9025, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.seq = 0

    def connect(self) -> bytes:
        if self.sock is not None:
            self.close()
        connect_targets = [(self.host, self.port)]
        if self.host in {"localhost", "127.0.0.1"}:
            connect_targets.append(("host.docker.internal", self.port))

        last_error: Exception | None = None
        for host, port in connect_targets:
            try:
                self.sock = socket.create_connection((host, port), timeout=self.timeout)
                self.sock.settimeout(self.timeout)
                self.host = host
                break
            except OSError as error:
                last_error = error
                self.sock = None
        if self.sock is None:
            raise ConnectionError(
                f"Could not connect to simulator on any of: "
                f"{', '.join(f'{h}:{p}' for h, p in connect_targets)}"
            ) from last_error

        self.sock.sendall(bytes.fromhex("f0000000"))
        atr_header = self._recv_exact(4)
        atr = self._recv_exact(atr_header[3])

        self.sock.sendall(bytes.fromhex("ff119678"))
        self._recv_exact(4)

        self.sock.sendall(bytes.fromhex("00c101fe3e"))
        self._recv_exact(5)
        return atr

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.sendall(bytes.fromhex("fe000000"))
        except OSError:
            pass
        finally:
            self.sock.close()
            self.sock = None

    def exchange_apdu(self, apdu: bytes) -> bytes:
        if self.sock is None:
            raise ConnectionError("Not connected to simulator")
        if len(apdu) > MAX_SHORT_APDU_LENGTH:
            raise ValueError(f"APDU too long for simulator transport: {len(apdu)} bytes")

        pcb = 0x40 if self.seq else 0x00
        packet = bytearray([0x00, pcb, len(apdu)])
        packet.extend(apdu)
        packet.append(xor_checksum(packet))
        self.sock.sendall(packet)

        header = self._recv_exact(3)
        if header[0] != 0x00:
            raise RuntimeError(f"Unexpected response type byte: 0x{header[0]:02X}")

        payload = self._recv_exact(header[2])
        checksum = self._recv_exact(1)[0]
        calculated = xor_checksum(header + payload)
        if checksum != calculated:
            raise ConnectionError(f"Checksum mismatch: expected 0x{calculated:02X}, got 0x{checksum:02X}")

        self.seq ^= 1
        return payload

    def _recv_exact(self, length: int) -> bytes:
        if self.sock is None:
            raise ConnectionError("Not connected to simulator")

        chunks = bytearray()
        while len(chunks) < length:
            chunk = self.sock.recv(length - len(chunks))
            if not chunk:
                raise ConnectionError("Connection closed by simulator")
            chunks.extend(chunk)
        return bytes(chunks)


class PCSCCardBackend:
    def __init__(self, reader_name: str | None = None):
        self.reader_name = reader_name
        self.manager = None
        self.reader = None
        self.selected_reader_name: str | None = None

    def connect(self) -> bytes:
        self.manager = SCardManager()
        available_readers = list(self.manager)
        if len(available_readers) == 0:
            raise RuntimeError("No PC/SC readers available")

        selected_reader = available_readers[0]
        if self.reader_name is not None:
            for reader in available_readers:
                if reader.name == self.reader_name:
                    selected_reader = reader
                    break
            else:
                available = ", ".join(reader.name for reader in available_readers)
                raise RuntimeError(
                    f"PC/SC reader '{self.reader_name}' not found. Available readers: {available}"
                )

        self.reader = selected_reader
        self.selected_reader_name = selected_reader.name
        self.reader.__enter__()
        return self.reader.get_atr()

    def close(self) -> None:
        if self.reader is not None:
            try:
                self.reader.disconnect()
            except Exception:
                pass
            self.reader = None
        if self.manager is not None:
            try:
                self.manager.ReleaseContext(self.manager.ctx)
            except Exception:
                pass
            self.manager = None
        self.selected_reader_name = None

    def exchange_apdu(self, apdu: bytes) -> bytes:
        if self.reader is None:
            raise ConnectionError("Not connected to card through PC/SC")
        return self.reader.transmit_apdu(apdu)


class NFCCardTransport(TransportProtocolBase):
    def __init__(
        self,
        backend: NFCCardBackend,
        sim_host: str = "localhost",
        sim_port: int = 9025,
        pcsc_reader: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.backend_name = backend
        self.sim_host = sim_host
        self.sim_port = sim_port
        self.pcsc_reader = pcsc_reader
        self.timeout = timeout
        self._rx_timestamp: float | None = None
        self.mode: Mode | None = None
        self._last_response: bytes | None = None
        self._backend: SimulatorCardBackend | PCSCCardBackend | None = None

    @property
    def rx_timestamp(self) -> float | None:
        return self._rx_timestamp

    @rx_timestamp.setter
    def rx_timestamp(self, value) -> None:
        self._rx_timestamp = value

    async def initialization(
        self,
        mode: Mode,
        reader_group_identifier: bytes = 16 * bytes.fromhex("00"),
        reader_group_sub_identifier: bytes = 16 * bytes.fromhex("00"),
        group_resolving_key: bytes = 16 * bytes.fromhex("00"),
        reader_group_identifier_list: list = [],
        spsm: bytes = bytes.fromhex("0080"),
        timeout: float | None = None,
        advertisement_version: int = 0x00,
        enable_uwb: bool = True,
    ) -> None:
        if mode != Mode.READER:
            raise InvalidModeError("NFCCardTransport only supports Reader mode")
        self.mode = mode
        if self.backend_name == "simulator":
            self._backend = SimulatorCardBackend(
                host=self.sim_host,
                port=self.sim_port,
                timeout=self.timeout,
            )
        else:
            self._backend = PCSCCardBackend(reader_name=self.pcsc_reader)
        atr = self._backend.connect()
        Global.logger.info(
            "Connected external NFC backend '%s' (ATR=%s)",
            self.backend_name,
            atr.hex().upper(),
        )

    async def wait_for_connection(self) -> None:
        if self._backend is None:
            raise ConnectionError("NFC backend not initialized")

    async def disconnect(self) -> None:
        if self._backend is not None:
            self._backend.close()
            self._backend = None
        self._last_response = None

    def was_timer_started(self):
        return False

    async def send_message(
        self,
        message: bytes,
        timeout: int | None = None,
    ) -> None:
        if self._backend is None:
            raise ConnectionError("NFC backend not initialized")
        if not isinstance(message, bytes):
            message = message.to_bytes()
        self._last_response = self._backend.exchange_apdu(message)
        self.rx_timestamp = time.time()

    async def get_message(self) -> tuple[bytes, int | None, int | None]:
        if self._last_response is None:
            raise NoDataReceivedError
        response = self._last_response
        self._last_response = None
        return response, None, None
