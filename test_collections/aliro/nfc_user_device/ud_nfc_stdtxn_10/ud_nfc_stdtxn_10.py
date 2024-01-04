from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from acwg_actuator.access_protocol.reader import Reader
from acwg_actuator.access_protocol import TransportProtocol
from acwg_actuator.access_protocol.apdu import TransactionCode
from acwg_actuator.access_protocol.defines import EXPEDITED_PHASE_AID

from ...support.aliro_test_case import AliroUserDeviceTestCase


class UD_NFC_STDTXN_10(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-NFC-STDTXN-1.0",
        "version": "0.0.1",
        "title": "UD-NFC-STDTXN-1.0",
        "description": """Verify conformance of User Device UT in AUTH0 command.""",
    }

    reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc4ed37a55515a9346fdae311f60be30421fa6dc61c5"
    )
    transaction_identifier = bytes(
        [
            0x41,
            0x65,
            0xA8,
            0x36,
            0x67,
            0xAD,
            0x0A,
            0xF5,
            0xAB,
            0x11,
            0x52,
            0x47,
            0x42,
            0x48,
            0x22,
            0xE0,
        ]
    )
    reader_identifier = bytes(
        [
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
            0xFF,
            0xEE,
            0xDD,
            0xCC,
            0xBB,
            0xAA,
            0x99,
            0x88,
            0x77,
            0x66,
            0x55,
            0x44,
            0x33,
            0x22,
            0x11,
            0x00,
        ]
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
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")

    async def execute(self) -> None:
        # Test step 1
        reader = Reader(
            transport_protocol=TransportProtocol.NFC, reader_key=None, reader_cert=None
        )  # private key(none is automatic generated) #public key #reader group identifier #identifier sub
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

    async def cleanup(self) -> None:
        logger.info("UD_NFC_STDTXN_10 Cleanup")
