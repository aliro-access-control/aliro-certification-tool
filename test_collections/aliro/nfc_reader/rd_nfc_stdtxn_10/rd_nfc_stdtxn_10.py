from aliro_actuator.access_protocol import TransportProtocol
from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID, STEPUP_PHASE_AID
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.trust_framework.endpoint import Endpoint
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase


class RD_NFC_STDTXN_10(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-STDTXN-1.0",
        "version": "0.0.1",
        "title": "RD-NFC-STDTXN-1.0",
        "description": """Verify conformance of Reader UT in AUTH0 command.""",
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
            TestStep("Step3: Bring Test Harness above Reader Device Under Test"),
            TestStep("Step4: Receive/Send Select command/response"),
            TestStep("Step5: Receive/Send AUTH0 command/response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")

    async def execute(self) -> None:
        # Test step 1
        endpoint = self.reader_endpoint()
        userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC, endpoints=[endpoint], mailbox=0x20
        )
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
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )
        userdevice.transaction_initiation()  # up to RATS command/ ATS response
        userdevice.start_new_session(
            ephemeral_key=KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
        )
        self.next_step()

        # Test step 4 Receive/Send Select command/response
        try:
            cmds_select = userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(error)
            return
        try:
            userdevice.handle_select(cmds_select)
        except AccessProtocolError as error:
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 5 Receive/Send Auth0 command/response
        try:
            cmds_auth0 = userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(error)
            return
        try:
            userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(error)
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_NFC_STDTXN_10 Cleanup")
