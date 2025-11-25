from aliro_actuator.access_protocol.apdu import (
    INS,
    Auth1Response,
    AuthenticationPolicy,
    Command,
    Response,
    StatusBytes,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    Auth0,
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSession, UserSessionState
from aliro_actuator.transport_protocol.ble_message_format import (
    OperationSourceInformation_Values,
    ReaderStatusInformation_Values,
    UnsolicitedReaderStatusReporting_Values,
    Notification_ID,
    Event_AttributeID,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
    SessionError,
    VersionError,
)
from aliro_actuator.access_document.access_document import AccessDocument
from aliro_actuator.access_document.revocation_document import RevocationDocument
from aliro_actuator.access_protocol.encryption import compute_cryptogram
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from aliro_actuator.trust_framework.errors import InvalidKeyError, KeyLookupFailed
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

import asyncio
import time
from binascii import hexlify
from os import urandom
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class BLEUWB_RDR_TIMEOUT_EXTENSION(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_TIMEOUT_EXTENSION",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_TIMEOUT_EXTENSION",
        "description": """Verify conformance of User Device UT in BLE discovery.""",
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
                "RD",
                "BLEUWB",
                "RD43"
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Establish L2CAP"),
            TestStep("Step2: Send Initiate AP Message ID"),
            TestStep("Step3: Wait for 1 second after receiving AUTH0 Command"),
            TestStep("Step4: Send General error with Busy attribute; after 1 second send AUTH0 Response"),
            TestStep("Step5: Handle AUTH1"),
            TestStep("Step6: Handle EXCHANGE"),
            TestStep("Step7: Handle AP Completed message"),
        ]

    def print_uwb_configuration(self, uwb_config: dict) -> None:
        logger.info("UWB Configuration is:")
        logger.info("-" * 50)
        for key, value in uwb_config.items():
            logger.info(f"{key:<12}: {value}")
        logger.info("-" * 50)

    async def handle_auth0_command(self, auth0_command: Command) -> list[Response]:
        """
        Parse auth0 command to prepare for response.

        Args:
            auth0_command (Command): The command to respond to.

        Raises:
            SessionError: Raised when the session is missing or in an invalid state.
            VersionError: Raised when the protocol version is not supported.
            NotImplementedError:
        """
        if auth0_command.ins != INS.AUTH0:
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
            auth0_command.expedited_phase_protocol_version
            not in self.userdevice.supported_versions
        ):
            await self.userdevice.failure_process(StatusBytes.CONDITIONS_OF_USE_NOT_SATISFIED)
            raise VersionError
        else:
            logger.info(
                "Requested version 0x{:04x} is supported (supported versions: {})".format(
                    auth0_command.expedited_phase_protocol_version,
                    ", ".join(str(hex(x)) for x in self.userdevice.supported_versions),
                )
            )

        logger.info("Saving AUTH0 data")
        try:
            self.userdevice.session.set_auth0_data(auth0_command)
        except InvalidKeyError:
            raise AccessProtocolError("Reader ephemeral key is invalid")
        logger.info("Reader ephemeral key is a valid key")

        # Setup UWB session id
        if self.userdevice.transport_protocol_type in [TransportProtocol.BLE_UWB, TransportProtocol.SOCKET_BLE]:
            if self.userdevice.enable_uwb:
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
                "{!r}".format(hexlify(self.userdevice.session.reader_group_identifier))
            )
            
        if hasattr(auth0_command, "tlv_check"):
            command_status = auth0_command.tlv_check
        else:
            command_status = True
        
        cryptogram = None

        if self.userdevice.session.get_transaction_type() == Transaction.STANDARD:
            logger.info("Standard transaction requested")
            self.userdevice.session.update_state(UserSessionState.AUTH0_STD_DONE)

        elif self.userdevice.session.get_transaction_type() == Transaction.FAST:
            logger.info("Fast transaction requested")
            logger.info("Looking for Kpersistent in storage")
            kpersistent = self.userdevice.storage.find_kpersistent(
                self.userdevice.session.reader_group_sub_identifier
            )
            if self.userdevice.fast_transaction_implemented and kpersistent is not None:
                logger.info(
                    "Kpersistent found: {!r}".format(hexlify(kpersistent))
                )
                logger.info("Creating Cryptogram")
                self.userdevice.session.derive_key_volatile_fast(
                    self.userdevice.transport_protocol_type, kpersistent
                )
                self.userdevice.session.create_encryption_engine_expedited()
                if self.userdevice.transport_protocol_type in [
                    TransportProtocol.BLE_UWB,
                    TransportProtocol.SOCKET_BLE,
                ]:
                    logger.info("Setting up BLE encryption")
                    self.userdevice.session.set_ble_encryption(self.userdevice.transport_protocol)
                    logger.info("Setting up UWB secure ranging")
                    await self.userdevice.transport_protocol.set_session_key(self.userdevice.session.UR_SK)

                doc_timestamp = None
                revoke_timestamp = None
                if self.userdevice.access_document is not None:
                    doc_timestamp = AccessDocument(self.userdevice.access_document).get_timestamp()
                if self.userdevice.revocation_document is not None:
                    revoke_timestamp = RevocationDocument(self.userdevice.revocation_document).get_timestamp()
                cryptogram = compute_cryptogram(
                    self.userdevice.session.cryptogram_SK,
                    signaling_bitmap=self.userdevice.get_signaling_bitmap(),
                    credential_signed_timestamp=doc_timestamp,
                    revocation_signed_timestamp=revoke_timestamp,
                )
            else:
                logger.info("Kpersistent not found, assigning random cryptogram")
                cryptogram = urandom(Auth0.CRYPTOGRAM_LEN)

            self.userdevice.session.update_state(UserSessionState.AUTH0_FAST_DONE)

        if command_status:
            status = StatusBytes.SUCCESS
        else:
            status = StatusBytes.COMMAND_NOT_COMPLIANT

        logger.info("Handling AUTH0 command done")
            
        return self.userdevice.apdu.create_auth0_response(
            credential_epubk=self.userdevice.session.get_credential_epubkey().as_bytes(),
            status=status, 
            cryptogram=cryptogram
        )

    async def send_auth0_response(self, auth0_response):
        logger.info("Sending AUTH0 response")
        try:
            await self.userdevice.apdu.handle_chaining_send_response(
                auth0_response, self.userdevice.transport_protocol, timeout=self.userdevice.timeout
            )
        except TimeoutError:
            await self.userdevice.handle_timeout()
            raise TimeoutError
        logger.info("Sending AUTH0 reponse done")

    async def th_sleep(self, delay: float):
        if self.userdevice.transport_protocol.rx_timestamp is not None:
            delay = max(delay - (time.perf_counter() - self.userdevice.transport_protocol.rx_timestamp), 0.0)
        logger.info(f"Test Harness sleeping for {delay}s")
        await asyncio.sleep(delay)
        self.userdevice.transport_protocol.rx_timestamp = None
        logger.info(f"Test Harness done sleeping")
        return None

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
        
        # Test step 1: Establish L2CAP
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        try:
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Set Reader Device Under Test in BLE advertising mode",
                    options={"OK": 1},
                )
            )
            await self.userdevice.setup_connection()
            self.userdevice.start_new_session()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 2: Send Initiate AP Message ID
        try:
            await self.userdevice.send_initiate_access_protocol_notification()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 3: Wait for 1 second after AUTH0 Command
        try:
            cmds_auth0 = await self.userdevice.wait_for_command(
                expected_command=INS.AUTH0
            )
            response = await asyncio.gather(
                self.th_sleep(1.0),
                self.handle_auth0_command(cmds_auth0)          
            )
            auth0_response = response[1]
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 4: Send General error with Busy attribute; after 1 second send AUTH0 Response
        try:
            await asyncio.gather(
                self.th_sleep(1.0),
                self.userdevice.send_event(Event_AttributeID.BUSY, None)
                )
            await self.send_auth0_response(auth0_response)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        
        self.next_step()
        # Step5: Handle AUTH1
        try:
            cmds_auth1 = await self.userdevice.wait_for_command(
                expected_command=INS.AUTH1
            )
            await self.userdevice.handle_auth1(cmds_auth1)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step6: Handle EXCHANGE
        try:
            cmds_exchange = await self.userdevice.wait_for_command(
                expected_command=INS.EXCHANGE
            )
            if cmds_exchange.ursk is None:
                self.mark_step_failure("Expected URSK tag in exchange command")
                return
            await self.userdevice.handle_exchange(cmds_exchange)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step7: Handle AP Completed message
        try:
            cmds = await self.userdevice.wait_for_message()
            self.userdevice.handle_reader_status_access_protocol_completed_message(cmds)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        await self.userdevice.transaction_termination()

    async def cleanup(self) -> None:
        logger.info("BLEUWB_RDR_TIMEOUT_EXTENSION Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
