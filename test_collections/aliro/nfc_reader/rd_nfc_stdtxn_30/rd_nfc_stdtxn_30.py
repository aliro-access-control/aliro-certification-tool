from aliro_actuator.access_protocol import TransportProtocol
from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase


class RD_NFC_STDTXN_30(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-STDTXN-3.0",
        "version": "0.0.1",
        "title": "RD-NFC-STDTXN-3.0",
        "description": """Verify conformance of Reader UT in CONTROL FLOW command.""",
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
            TestStep("Step6: Receive/Send AUTH1 command/response"),
            TestStep("Step7: Receive/Send CONTROL FLOW command/response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")

    async def execute(self) -> None:
        # Test step 1
        access_credential = self.reader_access_credential()
        userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential],
            mailbox=0x20,
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
                prompt="Set Reader Device Under Test in NFC polling mode",
                options={"OK": 1},
            )
        )
        await userdevice.transaction_initiation()  # up to RATS command/ ATS response
        userdevice.start_new_session(
            ephemeral_key=KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
        )
        self.next_step()

        # Test step 4 Receive/Send Select command/response
        try:
            cmds_select = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(error)
            return
        try:
            await userdevice.handle_select(cmds_select)
        except AccessProtocolError as error:
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 5 Receive/Send Auth0 command/response
        try:
            cmds_auth0 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(error)
            return
        try:
            await userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(error)
            return
        if not userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )
        self.next_step()

        # Test step 6 Receive/Send Auth1 command/response
        try:
            cmds_auth1 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(error)
            return
        try:
            await userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 7
        while True:
            try:
                cmds_control_flow = await userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(error)
                return

            if cmds_control_flow.ins == INS.CONTROL_FLOW:
                try:
                    await userdevice.handle_control_flow(cmds_control_flow)
                except AccessProtocolError as error:
                    self.mark_step_failure(error)
                    return
                self.next_step()
                break
            elif cmds_control_flow.ins == INS.EXCHANGE:
                try:
                    await userdevice.handle_exchange(cmds_control_flow)
                except AccessProtocolError as error:
                    self.mark_step_failure(error)
                    return
                # re-enter loop waiting for control flow
            else:
                self.mark_step_failure(f"Unexpected command {cmds_control_flow.ins}")
                return

    async def cleanup(self) -> None:
        logger.info("RD_NFC_STDTXN_30 Cleanup")
