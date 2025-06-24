from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    INS,
    StatusBytes,
    S1,
    S2,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    STEPUP_PHASE_AID,
    CSA_APPLICATION_TYPE,
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

from binascii import hexlify


class NFC_RDR_NEG_SEL_RSP_NO_COMMON_EXPEDITED_PROTOCOL_VERSION(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_NEG_SEL_RSP_NO_COMMON_EXPEDITED_PROTOCOL_VERSION",
        "version": "0.0.1",
        "title": "NFC_RDR_NEG_SEL_RSP_NO_COMMON_EXPEDITED_PROTOCOL_VERSION",
        "description": """Verify conformance of Reader UT in SELECT command.""",
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
            TestStep("Step4: Receive/Send Select command/response"),
            TestStep("Step5: Receive/Send CONTROL FLOW command/response"),
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
            if cmds_select.ins != INS.SELECT:
                raise AccessProtocolError(
                    "Tried to handle Select command, "
                    "but received command is not a select command"
                )

            if self.userdevice.session is None:
                raise SessionError("No Session")

            logger.info("Handling Select Command")
            if cmds_select.aid == EXPEDITED_PHASE_AID:
                logger.info(
                    "AID valid for expedited phase: {!r}".format(
                        hexlify(cmds_select.aid)
                    )
                )
                self.userdevice.session.update_state(UserSessionState.SELECT_DONE)
            elif cmds_select.aid == STEPUP_PHASE_AID:
                logger.info(
                    "AID valid for step-up phase: {!r}".format(hexlify(cmds_select.aid))
                )
                if not self.userdevice.session.state_valid(
                    [UserSessionState.AUTH1_DONE, UserSessionState.EXCHANGE_DONE]
                ):
                    raise AccessProtocolError(
                        "Step up phase can only be requested after standard expedited phase"
                    )
                self.userdevice.session.update_state(UserSessionState.SELECT_STEP_UP_DONE)
            else:
                logger.warning("Invalid AID")
                await self.userdevice.failure_process(StatusBytes.FILE_OR_APP_NOT_FOUND)
                raise InvalidAIDError(select_command.to_bytes(), select_command.aid)

            select_response = self.userdevice.apdu.create_select_response(
                cmds_select.aid,
                CSA_APPLICATION_TYPE,
                [0x0A00],
                status=StatusBytes.SUCCESS,
            )
            logger.info("Sending SELECT response")
            await self.userdevice.apdu.handle_chaining_send_response(
                select_response, self.userdevice.transport_protocol
            )
            logger.info("Handling SELECT command done")
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5 Receive/Send CONTROL FLOW command/response
        try:
            cmds_controlflow = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_control_flow(cmds_controlflow)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if cmds_controlflow.s1 != S1.FINISHED_WITH_FAILURE:
            self.mark_step_failure(
                "S1 value of CONTROL FLOW not '0x00 transaction finished with failure'"
            )
        if cmds_controlflow.s2 != S2.PROTOCOL_VERSION_NOT_SUPPORTED:
            self.mark_step_failure("S2 value of CONTROL FLOW not '0x27 protocol version not supported'")
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_RDR_NEG_SEL_RSP_NO_COMMON_EXPEDITED_PROTOCOL_VERSION Cleanup")
        await self.userdevice.transaction_termination()
