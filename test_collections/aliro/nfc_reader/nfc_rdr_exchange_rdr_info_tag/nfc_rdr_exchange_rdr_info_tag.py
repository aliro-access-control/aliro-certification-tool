from aliro_actuator.access_protocol.apdu import Auth1Response, INS
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_EXCHANGE_RDR_INFO_TAG(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_EXCHANGE_RDR_INFO_TAG",
        "version": "0.0.1",
        "title": "NFC_RDR_EXCHANGE_RDR_INFO_TAG",
        "description": """Verify conformance of Reader UT.""",
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
            await self.userdevice.transaction_initiation()  # including select
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
        if cmds_auth1.expected_response != Auth1Response.CREDENTIAL_PUBLIC_KEY:
            self.mark_step_failure(
                "Access Credential key type request is not endpoint public key!"
            )
            return
        try:
            await self.userdevice.handle_auth1(cmds_auth1, extra_tlv=bytes.fromhex("010203"))
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test Step 6 Receive/Send EXCHANGE command/response
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
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_RDR_EXCHANGE_RDR_INFO_TAG Cleanup")
        await self.userdevice.transaction_termination()
