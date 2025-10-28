from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    INS,
    StatusBytes,
    S1,
    S2,
    ReaderStatus,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
    Auth1,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
    SessionError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.access_protocol.authentication import (
    create_user_device_authentication,
)
from aliro_actuator.trust_framework.key import KeyPair
from aliro_actuator.trust_framework.errors import KeyLookupFailed
from aliro_actuator.access_protocol.tlv import TLV
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors
from binascii import hexlify


class NFC_RDR_NEG_AUTH1_WRONG_VALUES(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_NEG_AUTH1_WRONG_VALUES",
        "version": "0.0.1",
        "title": "NFC_RDR_NEG_AUTH1_WRONG_VALUES",
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
            TestStep("Step1: Initialization"),
            TestStep("Step2: Transaction initiation"),
            TestStep("Step3: Receive/Send AUTH0 command/response"),
            TestStep("Step4: Receive/Send AUTH1 command/response"),
            TestStep("Step5: Receive/Send EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        access_credential = self.reader_access_credential()
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential],
            mailbox=0x20,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
        self.next_step()

        # Test step 2
        # Display pop-up to put the Test Harness on the Reader device Under Test
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode",
                options={"OK": 1},
            )
        )
        try:
            await self.userdevice.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 3 Receive/Send Auth0 command/response
        try:
            cmds_auth0 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )
        self.next_step()

        # Test step 4 Receive/Send Auth1 command/response
        try:
            cmds_auth1 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            if cmds_auth1.ins != INS.AUTH1:
                raise AccessProtocolError(
                    "Tried to handle auth1 command, "
                    "but received command is not a auth1 command"
                )

            if self.userdevice.session is None:
                raise SessionError("No Session")
            if not self.userdevice.session.state_valid(
                [UserSessionState.AUTH0_FAST_DONE, UserSessionState.AUTH0_STD_DONE]
            ):
                state = self.userdevice.session.state
                await self.userdevice.failure_process(StatusBytes.INVALID_INSTRUCTION)
                raise SessionError("unexpected state for auth1 command: {}".format(state))

            logger.info("Handling AUTH1 Command")
            if cmds_auth1.certificate_data is not None:
                logger.info("AUTH1 Command contains certificate")

                reader_issuer_public_key = self.userdevice.session.get_reader_group_identifier_key()
                self.userdevice.session.set_cert_and_verify(
                    cmds_auth1.certificate_data, reader_issuer_public_key
                )

            if hasattr(self.userdevice.session, "cert_decoded") and not self.userdevice.session.cert_decoded:
                logger.error("Error decoding certificate")
                await self.userdevice.failure_process(StatusBytes.GENERIC_ERROR)
                raise AccessProtocolError("Certificate decoding failed")
            if hasattr(self.userdevice.session, "cert_verified") and not self.userdevice.session.cert_verified:
                logger.error("Error verifying certificate")
                await self.userdevice.failure_process(StatusBytes.SECURITY_STATUS_NOT_SATISFIED)
                raise AccessProtocolError("Certificate verification failed")

            await self.userdevice.check_reader_authentication_data(cmds_auth1.reader_signature)

            try:
                logger.info("Creating shared keys")
                self.userdevice.session.set_shared_key()
                self.userdevice.session.derive_key_volatile(self.userdevice.transport_protocol_type)
                if self.userdevice.transport_protocol_type in [
                    TransportProtocol.BLE_UWB,
                    TransportProtocol.SOCKET_BLE,
                ]:
                    logger.info("Setting up BLE encryption")
                    self.userdevice.session.set_ble_encryption(self.transport_protocol)
                    logger.info("Setting up UWB secure ranging")
                    await self.userdevice.transport_protocol.set_session_key(self.session.UR_SK)

                logger.info("Creating Kpersistent")
                self.userdevice.storage.add_kpersistent(
                    kpersistent=self.userdevice.session.derive_key_persistent(
                        self.userdevice.transport_protocol_type
                    ),
                    reader_group_sub_id=self.userdevice.session.reader_group_sub_identifier,
                )
            except KeyLookupFailed as error:
                # could not find reader public key
                await self.userdevice.failure_process(StatusBytes.GENERIC_ERROR)
                raise error

            logger.info("Creating user device authentication")
            device_authentication = create_user_device_authentication(
                self.userdevice.session.reader_identifier,
                self.userdevice.session.get_credential_epubkey(),
                self.userdevice.session.reader_epubk,
                self.userdevice.session.transaction_identifier,
            )
            signature = self.userdevice.session.access_credential.sign(
                device_authentication.to_bytes()
            )
            logger.debug(
                "Created user device authentication_data signature: {!r}".format(
                    hexlify(signature)
                )
            )

            if self.userdevice.session.encryption_expedited is None:
                raise AccessProtocolError("no encryption engine found")

            self.userdevice.session.update_state(UserSessionState.AUTH1_DONE)
            self.chaining_command = cmds_auth1.chaining
            
            auth1_payload: list[tuple[int, bytes | list]] = [
                (Auth1.CREDENTIAL_PUBK_TAG, self.userdevice.session.access_credential.get_access_credential_public_key().as_bytes()),
                (0x88, signature), # wrong tag
                (Auth1.SIGNALING_BITMAP_TAG, self.userdevice.get_signaling_bitmap())
            ]
            auth1_payload_tlv = TLV(auth1_payload)
            encrypted_payload, tag = self.userdevice.session.encryption_expedited.encrypt(
                auth1_payload_tlv.to_bytes(),
            )
            payload = bytes([*encrypted_payload, *tag])
            auth1_response = self.userdevice.apdu.create_response(payload, StatusBytes.SUCCESS)

            await self.userdevice.apdu.handle_chaining_send_response(
                auth1_response, self.userdevice.transport_protocol
            )

            logger.info("Handling AUTH1 command done")
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test Step 5 Receive/Send EXCHANGE command/response
        try:
            cmds_exchange = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_exchange(cmds_exchange)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if not self.userdevice.session.state_valid(UserSessionState.TRANSACTION_COMPLETE):
            self.mark_step_failure("Exchange message did not include reader status")
            return
        if ReaderStatus(cmds_exchange.reader_status).is_success:
            self.mark_step_failure("Exchange indicates success, when it should indicate failure")
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_RDR_NEG_AUTH1_WRONG_VALUES Cleanup")
        await self.userdevice.transaction_termination()
