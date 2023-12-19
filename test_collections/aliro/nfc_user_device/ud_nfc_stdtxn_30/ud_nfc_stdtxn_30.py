from aliro_actuator.access_protocol import TransportProtocol
from aliro_actuator.access_protocol.apdu import TransactionCode
from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID
from aliro_actuator.access_protocol.reader import Reader

from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase


class UD_NFC_STDTXN_30(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-NFC-STDTXN-3.0",
        "version": "0.0.1",
        "title": "UD-NFC-STDTXN-3.0",
        "description": """Verify conformance of User Device UT in AUTH0 command.""",
    }

    reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8"
        "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
        "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
    )

    transaction_identifier = bytes.fromhex("4165A83667AD0AF5AB115247424822E0")
    reader_identifier = bytes.fromhex(
        "00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100"
    )

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
            TestStep("Step3: Set the User Device UT"),
            TestStep("Step4: Send/Receive Select command/response"),
            TestStep("Step5: Send/Receive AUTH0 command/response"),
            TestStep("Step6: Send/Receive AUTH1 command/response"),
            TestStep("Step7: Send/Receive CONTROL_FLOW command/response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")

    async def execute(self) -> None:
        # Test step 1
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()

        # Initialize Aliro NFC Reader
        reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
        )
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
        reader.transaction_initiation()  # up to RATS command/ ATS response
        self.next_step()

        # Test step 4
        reader.command_select(aid=EXPEDITED_PHASE_AID)
        self.next_step()

        # Test step 5
        reader.command_auth0(
            transaction=0,
            transaction_code=TransactionCode.UNLOCK,
            protocol_version=0x0100,
            reader_epubk=self.reader_ePuBK,
            transaction_identifier=self.transaction_identifier,
            reader_identifier=self.reader_identifier,
        )
        self.next_step()

        # Test step 6
        reader.command_auth1(
            # TODO: command_parameters not supported in command_auth1
            command_parameters=0,
            reader_epubk=self.reader_ePuBK,
            endpoint_epubk=0,  # Should be From AUTH0 Response
            transaction_identifier=self.transaction_identifier,
            reader_identifier=self.reader_identifier,
        )
        self.next_step()

        # Test step 7
        reader.command_control_flow(
            S1_parameter=0,
            S2_parameter=1,
        )
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_NFC_STDTXN_30 Cleanup")
