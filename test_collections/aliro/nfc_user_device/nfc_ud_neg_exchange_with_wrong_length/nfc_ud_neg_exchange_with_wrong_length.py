from binascii import hexlify

from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    INS,
    Transaction,
    ReaderStatus,
    Response,
    S2,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
    Exchange,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseDataError,
    InvalidResponseError,
    SessionError,
    InvalidStatusError
)
from aliro_actuator.access_protocol.encryption import (
    EncryptionEngine,
    EncryptionMissingError,
    VerificationError,
)
from aliro_actuator.access_protocol.reader import Reader, ReaderFailureState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from aliro_actuator import Global
from aliro_actuator.access_protocol.tlv import TLV
from enum import Enum

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors
import random

class ReaderState(Enum):
    EXPEDITED = 1
    STEPUP = 2

class NFC_UD_NEG_EXCHANGE_WITH_WRONG_LENGTH(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_NEG_EXCHANGE_WITH_WRONG_LENGTH",
        "version": "0.0.1",
        "title": "NFC_UD_NEG_EXCHANGE_WITH_WRONG_LENGTH",
        "description": """Expedited Phase With EXCHANGE command with wrong length/value for tag""",
    }

    reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8"
        "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
        "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
    )
    reader_ePrivK = bytes.fromhex(
        "3c0f74114cd2a021e8066efbaa31dbb97ef0054272192606fd96633a04f66214"
    )
    transaction_identifier = bytes.fromhex("4165A83667AD0AF5AB115247424822E0")

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set to polling mode"),
            TestStep("Step3: Transaction initiation"), #include select command and response
            TestStep("Step4: Send/Receive AUTH0 command/response"),
            TestStep("Step5: Send/Receive AUTH1 command/response"),
            TestStep("Step6: Send EXCHANGE command with wrong length/value for tag and Receive EXCHANGE response"),
            TestStep("Step7: Send/Receive EXCHANGE command/response with Tag 0x97"),
        ]

    async def create_exchange_command_with_wrong_length_tag_value(
        self, 
        mailbox_commands: bytes | None = None,
        notify: bytes | None = None,
        reader_status: int | None = None,
        ursk: bool = False,
        update_doc: bytes | None = None,
        encryption: EncryptionEngine | None = None
        ):

        Global.logger.info("Creating EXCHANGE command with wrong length/tag value")
        if encryption is None:
            raise EncryptionMissingError

        Global.logger.debug("Creating TLV")
        payload_list: list[tuple[int, bytes | list]] = []
        if mailbox_commands is not None:
            Global.logger.debug("Adding mailbox commands")
            payload_list.append((Exchange.MAILBOX_TAG, mailbox_commands))
        if notify is not None:
            Global.logger.debug("Adding notify")
            payload_list.append((Exchange.NOTIFY_TAG, notify))
        if reader_status is not None:
            Global.logger.debug("Adding reader status: 0x{:04x}".format(reader_status))
            payload_list.append(
                (Exchange.READER_STATUS_TAG, reader_status.to_bytes(2, "big"))
            )
        if ursk:
            Global.logger.debug("Adding URSK")
            payload_list.append((Exchange.URSK_TAG, bytes()))
        if update_doc is not None:
            Global.logger.debug("Adding update doc")
            payload_list.append((Exchange.UPDATE_DOC_TAG, update_doc))

        payload_tlv = TLV(payload_list)
        payload = bytearray(payload_tlv.to_bytes())
        # Assign a wrong value to length byte in exchange command payload. 
        payload[1] = min(0xFF, len(payload) + 0x64)
        payload = bytes(payload)

        Global.logger.debug("Payload: {!r}".format(hexlify(payload)))

        Global.logger.info("encrypting EXCHANGE command payload")
        encrypted_payload, tag = encryption.encrypt(
            payload,
        )
        payload = encrypted_payload + tag

        command =  self.reader.apdu.create_command(
            cla=0x80,
            ins=INS.EXCHANGE,
            p1=0x00,
            p2=0x00,
            data=payload,
            le=0x00,
        )

        try:
            response = await self.reader.apdu.handle_chaining_send_command(
                "EXCHANGE", command, self.reader.transport_protocol, timeout=self.reader.timeout
            )
        except TimeoutError:
            await self.reader.handle_timeout()
            raise TimeoutError

        Global.logger.info("Received response")
        response = self.reader.apdu.parse_response(response, INS.EXCHANGE, encryption)

        return response

    async def handle_exchange_with_wrong_tag_value(
        self,
        atomic_session: bool = False,
        read_requests: list[tuple[int, int]] | None = None,
        write_requests: list[tuple[int, bytes]] | None = None,
        set_requests: list[tuple[int, int, int]] | None = None,
        notify: TLV | None = None,
        ursk: bool = False,
        update_doc: bytes | None = None,
        reader_status: int | None = None,
        reader_state: ReaderState = ReaderState.EXPEDITED,
    ):
        
        wrong_read_tag_value = 0x27      # Actual read tag value is 0x87, assigning to some wrong value.
        if self.reader.session is None:
            raise SessionError("No Session")

        Global.logger.info("Start handling EXCHANGE")

        Global.logger.debug("Creating mailbox commands TLV")
        mailbox_commands_list: list[tuple[int, bytes | list]] = []
        if read_requests is not None:
            Global.logger.debug("Adding read requests with wrong tag value")
            for read_request in read_requests:
                mailbox_commands_list.append(
                    (
                        wrong_read_tag_value,                         # Processing EXCHANGE command with wrong tag value
                        read_request[0].to_bytes(2, "big")
                        + read_request[1].to_bytes(2, "big"),
                    )
                )
        if write_requests is not None:
            for write_request in write_requests:
                mailbox_commands_list.append(
                    (
                        Exchange.WRITE_TAG,
                        write_request[0].to_bytes(2, "big") + write_request[1],
                    )
                )
        if set_requests is not None:
            Global.logger.debug("Adding set requests")
            for set_request in set_requests:
                mailbox_commands_list.append(
                    (
                        Exchange.SET_TAG,
                        set_request[0].to_bytes(2, "big")
                        + set_request[1].to_bytes(2, "big")
                        + set_request[2].to_bytes(1, "big"),
                    )
                )
        mailbox_commands_tlv = TLV(mailbox_commands_list)
        if len(mailbox_commands_tlv.to_data()) > 0:
            Global.logger.info(
                "mailbox commands are part of an atomic session: {}".format(
                    atomic_session
                )
            )
            atomic_session_tlv = TLV(
                [(Exchange.ATOMIC_SESSION_TAG, atomic_session.to_bytes(1, "big"))]
            )
            mailbox_commands = (
                atomic_session_tlv.to_bytes() + mailbox_commands_tlv.to_bytes()
            )
            Global.logger.debug("Creating mailbox commands TLV Done")
        else:
            mailbox_commands = None
            Global.logger.debug("No mailbox commands in this EXCHANGE")

        if reader_state == ReaderState.EXPEDITED:
            Global.logger.debug("Using expedited encryption key")
            encryption = self.reader.session.encryption_expedited
        elif reader_state == ReaderState.STEPUP:
            Global.logger.debug("Using step up encryption key")
            encryption = self.reader.session.encryption_stepup
        else:
            encryption = None

        if notify is not None:
            notify_bytes = notify.to_bytes()
        else:
            notify_bytes = None

        try:
            response = await self.create_exchange_command_with_wrong_length_tag_value(
                mailbox_commands=mailbox_commands,
                notify=notify_bytes,
                reader_status=reader_status,
                ursk=ursk,
                update_doc=update_doc,
                encryption=encryption,
            )
        except InvalidResponseError as error:
            Global.logger.error("EXCHANGE response format invalid")
            await self.reader.failure_process(ReaderStatus.INVALID_DATA_FORMAT)
            raise error
        except VerificationError as error:
            Global.logger.error("EXCHANGE response decryption failed")
            await self.reader.failure_process(ReaderStatus.INVALID_DATA_CONTENT)
            raise error

        Global.logger.info("Handling EXCHANGE response")
        if len(response.status_code) != 4:
            await self.reader.failure_process(S2.NONE, failure_state=ReaderFailureState.B1_B2_ERROR)
            raise AccessProtocolError(
                "EXCHANGE payload status has invalid length: {!r}".format(
                    response.status_code
                )
            )
        if response.status_code == bytes.fromhex("00020000"):
            raise InvalidResponseDataError(response.decrypted_payload,
                "EXCHANGE returned success status at end of payload: {!r}".format(
                    response.status_code
                )
            )
        Global.logger.info(
            "All requests handled successfully, status: {!r}".format(
                response.status_code
            )
        )

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
        )
        
    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
        self.next_step()

        # Test step 2
        # Display pop-up to put the User Device UT on the TH
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
            )
        )
        self.next_step()

        # Test step 3
        try:
            await self.reader.transaction_initiation()  # including SELECT command
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 4
        authentication_policy = random.randint(
            AuthenticationPolicy.USER_DEVICE, 
            AuthenticationPolicy.FORCE_USER_AUTHENTICATION
        )
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy(authentication_policy),
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        bitmap_1 = self.reader.session.signaling_bitmap[1]
        if not (bitmap_1 & (1 << 4) == (1 << 4)):
            self.mark_step_failure("Auth1 response indicates mailbox cannot be read")
            return
        self.next_step()
        
        # Test step 6
        read_request = [(0x00C, 0x010)] 
        try:
            await self.handle_exchange_with_wrong_tag_value(
                False, read_requests = read_request
            )
        except InvalidStatusError as error:
            Global.logger.info(
                "EXCHANGE command response SW does not indicate success as expected, "
                "received status: 0x{:04x}".format(error.status)
            )
            self.mark_step_failure(str(error))
            return
        except (AccessProtocolError, InvalidResponseDataError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        else:
            Global.logger.info("EXCHANGE with wrong length generated response with error status code")
            
        self.next_step()

        # Test step 7
        try:
            self.reader.session.encryption_expedited = None
            await self.reader.handle_control_flow(s2=S2.NONE)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_NEG_EXCHANGE_WITH_WRONG_LENGTH Cleanup")
        await self.reader.transaction_termination()
