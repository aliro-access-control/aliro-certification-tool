from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from acwg_actuator.access_protocol.user_device import UserDevice
from acwg_actuator.trust_framework.endpoint import Endpoint
from acwg_actuator.trust_framework.key import KeyPair, PublicKey
from acwg_actuator.access_protocol import TransportProtocol
from acwg_actuator.access_protocol.defines import EXPEDITED_PHASE_AID

from ...support.aliro_test_case import AliroReaderTestCase


class RD_NFC_STDTXN_10(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-STDTXN-1.0",
        "version": "0.0.1",
        "title": "RD-NFC-STDTXN-1.0",
        "description": """Verify conformance of Reader UT in AUTH0 command.""",
    }

    # Reader Device UT #1
    reader_identifier_list_1 = [bytes.fromhex("da5bec40670cfe227fe9947f091b419e5a0fc53977e414a6db5e5c7574d337a8")]
    reader_public_key_1 = PublicKey(bytes.fromhex("04fe592041499a537cdf32102d18148d6f3fcf3143bd28d7d1a33237b727ef7531e1054b6c15ddad0ff5d5b3f014cba7db020c4c67b06d0b712d55514685e6b28e"))

    # Reader Device UT #2
    reader_identifier_list_2 = [bytes.fromhex("d0433f8f799ae90e9d00bfa6cd5cda61092701e4ef59d870dc5da262ed9d7de0")]
    reader_public_key_2 = PublicKey(bytes.fromhex("04eb26e9e125da3b959131aae5d5addea35770565aad26651dc638d46aa377b1ad207def423cc818e550dc6500a2c0c446ae22ecaa28ac294daff8c3917b5f627d"))

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0df608de904c920ac29f72bd4274c2edc810a93e240bf5d6394a92c9766b690b2bf5128ae70d6e29257ea786"
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
        endpoint_keypair = KeyPair()  # create endpoint key pair.
        endpoints = [
            Endpoint(
                endpoint_keypair,
                self.reader_public_key_1,
                self.reader_identifier_list_1,
            ),
            Endpoint(
                endpoint_keypair,
                self.reader_public_key_2,
                self.reader_identifier_list_2,
            ),
        ]  # set endpoint keypair + table to retrieve Reader public key using reader identifier
        userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC, endpoints=endpoints, mailbox=0x20
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
        self.next_step()
        userdevice.transaction_initiation()  # up to RATS command/ ATS response
        self.next_step()

        # Test step 4
        userdevice.wait_for_command()
        userdevice.response_select(
            aid=EXPEDITED_PHASE_AID, type=0x0000, protocol_versions=[0x0100]
        )
        self.next_step()

        # Test step 5
        userdevice.wait_for_command()
        userdevice.response_auth0(endpoint_epubk=self.endpoint_ePuBK)
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_NFC_STDTXN_10 Cleanup")
