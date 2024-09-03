from aliro_actuator.access_protocol.apdu import S1, S2, Response
from aliro_actuator.access_protocol.defines import (
    CSA_APPLICATION_TYPE,
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    Select,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import create_proprietary_information
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidAIDError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class RD_NFC_SELECT_12(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-SELECT-1.2",
        "version": "0.0.1",
        "title": "RD-NFC-SELECT-1.2",
        "description": """Verify conformance of Reader UT in SELECT command with response AID.""",
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
            TestStep("Step4: Receive/Send SELECT command/response"),
            TestStep("Step4: Receive/Send CONTROL FLOW command/response"),
        ]

    async def setup(self) -> None:
        logger.info("RD_NFC_SELECT_12 setup")
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
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )
        await self.userdevice.setup_connection()  # up to RATS command/ ATS response
        self.userdevice.start_new_session()
        self.next_step()

        # Test step 4 Receive/Send Select command/response
        try:
            cmds_select = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            if cmds_select.aid != EXPEDITED_PHASE_AID:
                logger.warning("Invalid AID")
                raise InvalidAIDError(cmds_select.to_bytes(), cmds_select.aid)

            await self.userdevice.response_select(
                bytes.fromhex("A000000909ACCE55FE"),
                CSA_APPLICATION_TYPE,
                [PROTOCOL_VERSION],
            )
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5 Receive/Send CONTROL FLOW command/response
        try:
            cmds_control_flow = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_control_flow(cmds_control_flow)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if cmds_control_flow.s1 != S1.FINISHED_WITH_FAILURE:
            self.mark_step_failure(
                "control flow did not indicate finished with failure"
            )
        if cmds_control_flow.s2 != S2.NONE:
            self.mark_step_failure("control flow did not indicate no information")
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_NFC_SELECT_12 Cleanup")
        await self.userdevice.transaction_termination()
