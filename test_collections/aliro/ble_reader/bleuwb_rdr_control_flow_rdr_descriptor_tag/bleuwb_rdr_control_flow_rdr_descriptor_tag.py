from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    INS,
    StatusBytes,
    Command,
    Transaction,
    TLV,
    S1,
    S2,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
    Auth0,
)
from aliro_actuator.transport_protocol.ble_message_format import (
    BleAttribute,
    BleMessage,
    Event_AttributeID, GeneralError_Values,
    Notification_ID,
    UWB_AttributeID,
    ProtocolType,
    UWB_RangingService_ID,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
    SessionError,
    VersionError,
)
from aliro_actuator.access_protocol.encryption import (
    VerificationError,
)
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from aliro_actuator.trust_framework.errors import (
    InvalidKeyError,
    KeyLookupFailed,
)
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from binascii import hexlify
from ...support.aliro_test_case import AliroReaderTestCase, log_errors
from aliro_actuator import Global

class BLEUWB_RDR_CONTROL_FLOW_RDR_DESCRIPTOR_TAG(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_CONTROL_FLOW_RDR_DESCRIPTOR_TAG",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_CONTROL_FLOW_RDR_DESCRIPTOR_TAG",
        "description": """Verify conformance of Reader UT in AUTH1 command.""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector

    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Transaction initiation"),
            TestStep("Step2: Receive/Send AUTH0 command/response"),
            TestStep("Step3: Receive/Send event message command/response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        self.access_credential = self.reader_access_credential(add_issuer_public_key=True)
        group_resolving_key = self.reader_group_resolving_key()
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.BLE_UWB,
            access_credentials=[self.access_credential],
            mailbox=0x20,
            group_resolving_key=group_resolving_key,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
        )

    @log_errors
    async def execute(self) -> None:
        # Done in setup
        issuer_group_id = self.access_credential.reader_id_key_list[1][0]
        prompt = "In case LOAD_CERT is used set correct group ID"
        prompt += "Set the reader_group_identifier of the reader device to: {}\n".format(hexlify(issuer_group_id))
        prompt += "to the Access Credential of the reader device\n"

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt=prompt,
                options={"OK": 1},
            )
        )

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in BLE advertising mode",
                options={"OK": 1},
            )
        )

        # Test step 1: Transaction Initiation & Send initiate access protocol notification
        try:
            await self.userdevice.transaction_initiation()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 2 Receive/Send Auth0 command/response
        try:
            cmds_auth0 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            if cmds_auth0.ins != INS.AUTH0:
                raise AccessProtocolError(
                    "Tried to handle auth0 command, "
                    "but received command is not a auth0 command"
                )

            if self.userdevice.session is None:
                raise SessionError("No Session")
            if not self.userdevice.session.state_valid(UserSessionState.SELECT_DONE) and (
                self.userdevice.transport_protocol_type != TransportProtocol.BLE_UWB
                and self.userdevice.transport_protocol_type != TransportProtocol.SOCKET_BLE
            ):
                state = self.userdevice.session.state
                await self.userdevice.failure_process(StatusBytes.INVALID_INSTRUCTION)
                raise SessionError("unexpected state for auth0 command: {}".format(state))

            # New user credential ephemeral key is set whenever sending an Auth0 response
            self.userdevice.set_credential_ephemeral_key()
            
            logger.info("Handling AUTH0 Command")
            if (
                cmds_auth0.expedited_phase_protocol_version
                not in self.userdevice.supported_versions
            ):
                await self.userdevice.failure_process(StatusBytes.CONDITIONS_OF_USE_NOT_SATISFIED)
                raise VersionError
            else:
                logger.info(
                    "Requested version 0x{:04x} is supported (supported versions: {})".format(
                        cmds_auth0.expedited_phase_protocol_version,
                        ", ".join(str(hex(x)) for x in self.userdevice.supported_versions),
                    )
                )

            logger.info("Saving AUTH0 data")
            try:
                self.userdevice.session.set_auth0_data(cmds_auth0)
            except InvalidKeyError:
                raise AccessProtocolError("Reader ephemeral key is invalid")
            logger.info("Reader ephemeral key is a valid key")

            # Setup UWB session id
            if (
                self.userdevice.transport_protocol_type == TransportProtocol.BLE_UWB
                or self.userdevice.transport_protocol_type == TransportProtocol.SOCKET_BLE
            ):
                await self.userdevice.transport_protocol.driver.session_init(
                    session_id=self.userdevice.session.transaction_identifier[-4:]
                )

            logger.info("Looking up access credential")
            for access_credential in self.userdevice.access_credentials:
                if access_credential.has_identifier(self.userdevice.session.reader_group_identifier):
                    self.userdevice.session.set_access_credential(access_credential)
                    logger.info("Access credential found")
                    try:
                        key = access_credential.get_reader_public_key(
                            self.userdevice.session.reader_group_identifier
                        ).as_bytes()
                        logger.info(
                            "Reader public key in access credential: {!r}".format(
                                hexlify(key)
                            )
                        )
                    except KeyLookupFailed:
                        pass

                    break
            else:
                raise AccessProtocolError(
                    "Could not find key for reader identifier in access credential: "
                    "{!r}".format(hexlify(self.session.reader_group_identifier))
                )

            if self.userdevice.session.get_transaction_type() == Transaction.STANDARD:
                logger.info("Standard transaction requested")
                self.userdevice.session.update_state(UserSessionState.AUTH0_STD_DONE)

                credential_epubk = self.userdevice.session.get_credential_epubkey().as_bytes()
                data_tlv: list[tuple[int, bytes | list]] = [
                    (0x88, credential_epubk), # wrong tag
                ]
                data_bytes = TLV(data_tlv)
                if hasattr(cmds_auth0, "tlv_check"):
                    status = cmds_auth0.tlv_check
                else:
                    status = True    
                if status:
                    command_status = StatusBytes.SUCCESS
                else:
                    command_status = StatusBytes.COMMAND_NOT_COMPLIANT
                
                auth0_response = self.userdevice.apdu.create_response(data_bytes.to_bytes(), command_status)
                await self.userdevice.apdu.handle_chaining_send_response(
                    auth0_response, self.userdevice.transport_protocol
                )
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )
        self.next_step()

        # Test step 3 Receive/Send event message
        try:
            event_message = await self.userdevice.wait_for_message()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        if (
            event_message.header == ProtocolType.NOTIFICATION
            and event_message.id == Notification_ID.EVENT
        ):
            try:
                self.userdevice.handle_event_message(event_message)
                if event_message.attribute.id != Event_AttributeID.GENERAL_ERROR:
                    self.mark_step_failure("Did not receive General Error Attribute ID")
                if event_message.reader_descriptor is None:
                    self.mark_step_failure("Did not receive Reader Descriptor Attribute ID")
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return
        else:
            self.mark_step_failure("Did not receive Event Message ID")
            return
        self.next_step()
       
    async def cleanup(self) -> None:
        logger.info("BLEUWB_RDR_CONTROL_FLOW_RDR_DESCRIPTOR_TAG Cleanup")
        await self.userdevice.transaction_termination()
