from binascii import hexlify

from aliro_actuator.access_protocol.apdu import INS, StatusBytes
from aliro_actuator.access_protocol.authentication import (
    create_reader_authentication,
    create_user_device_authentication,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
    KeyLookupFailed,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class RD_NFC_EXCHANGE_17(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-EXCHANGE-1.7",
        "version": "0.0.1",
        "title": "RD-NFC-EXCHANGE-1.7",
        "description": """Verify conformance of Reader UT in EXCHANGE command.""",
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
            TestStep("Step2: Set Reader Device Under Test in polling mode"),
            TestStep("Step3: Transaction initiation"),
            TestStep("Step4: Receive/Send AUTH0 command/response"),
            TestStep("Step5: Receive/Send AUTH1 command/response"),
            TestStep("Step6: Receive/Send EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("RD_NFC_EXCHANGE_1.7 setup")
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
        # Display pop-up to set the Reader Device Under Test in polling mode
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode",
                options={"OK": 1},
            )
        )
        self.next_step()

        # Test step 3
        # Display pop-up to put the Test Harness on the Reader device Under Test
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode",
                options={"OK": 1},
            )
        )
        try:
            await self.userdevice.transaction_initiation()  # up to RATS command/ ATS response
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 4 Receive/Send Auth0 command/response
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

        # Test step 5 Receive/Send Auth1 command/response
        try:
            cmds_auth1 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.check_reader_authentication_data(
                cmds_auth1.reader_signature
            )

            try:
                logger.info("Creating shared keys")
                self.userdevice.session.set_shared_key()
                self.userdevice.session.derive_key_volatile(
                    self.transport_protocol_type
                )

                logger.info("Creating Kpersistent")
                self.userdevice.storage.add_kpersistent(
                    kpersistent=self.userdevice.session.derive_key_persistent(
                        self.userdevice.transport_protocol_type
                    ),
                    reader_group_sub_id=self.userdevice.session.reader_group_sub_identifier,
                )
            except KeyLookupFailed as error:
                # could not find reader public key
                await self.failure_process(StatusBytes.GENERIC_ERROR)
                raise error

            logger.info("Creating user device authentication")
            device_authentication = create_user_device_authentication(
                self.userdevice.session.reader_identifier,
                self.userdevice.session.get_credential_epubkey(),
                self.userdevice.session.reader_epubk,
                self.userdevice.session.transaction_identifier,
            )
            signature = self.session.access_credential.sign(
                device_authentication.to_bytes()
            )
            logger.debug(
                "Created user device authentication_data signature: {!r}".format(
                    hexlify(signature)
                )
            )

            await self.userdevice.response_auth1(
                None,
                None,
                cmds_auth1.expected_response,
                signature,
                self.userdevice.session.encryption_expedited,
                StatusBytes.SUCCESS,
                signaling_bitmap=self.userdevice.get_signaling_bitmap(),
                check_validity=False,
            )
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 6
        while True:
            try:
                cmds_exchange = await self.userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return

            if cmds_exchange.ins == INS.EXCHANGE:
                try:
                    await self.userdevice.handle_exchange(cmds_exchange)
                except AccessProtocolError as error:
                    self.mark_step_failure(str(error))
                    return
                if self.userdevice.session.state_valid(
                    UserSessionState.TRANSACTION_COMPLETE
                ):
                    break
                # re-enter loop waiting for control flow
            else:
                self.mark_step_failure(f"Unexpected command {cmds_exchange.ins}")
                return
        logger.info(
            "Received EXCHANGE command with reader status: 0x{:04x}".format(
                cmds_exchange.reader_status.value
            )
        )

    async def cleanup(self) -> None:
        logger.info("RD_NFC_EXCHANGE_1.7 Cleanup")
        await self.userdevice.transaction_termination()
