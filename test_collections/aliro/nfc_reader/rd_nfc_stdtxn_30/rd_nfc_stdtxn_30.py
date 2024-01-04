from aliro_actuator.access_protocol import TransportProtocol
from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.trust_framework.endpoint import Endpoint
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
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

    # Reader Device UT #1
    reader_identifier_list_1 = [
        bytes.fromhex(
            "da5bec40670cfe227fe9947f091b419e5a0fc53977e414a6db5e5c7574d337a8"
        )
    ]
    reader_public_key_1 = PublicKey(
        bytes.fromhex(
            "04fe592041499a537cdf32102d18148d6f3fcf3143bd28d7d1a33237b727ef7531e1054b6c"
            "15ddad0ff5d5b3f014cba7db020c4c67b06d0b712d55514685e6b28e"
        )
    )

    # Reader Device UT #2
    reader_identifier_list_2 = [
        bytes.fromhex(
            "d0433f8f799ae90e9d00bfa6cd5cda61092701e4ef59d870dc5da262ed9d7de0"
        )
    ]
    reader_public_key_2 = PublicKey(
        bytes.fromhex(
            "04eb26e9e125da3b959131aae5d5addea35770565aad26651dc638d46aa377b1ad207def42"
            "3cc818e550dc6500a2c0c446ae22ecaa28ac294daff8c3917b5f627d"
        )
    )

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0df608de904c920ac29f72bd4274c2edc810"
        "a93e240bf5d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector
    endpoint_public_key = bytes.fromhex(
        "04ed1c8b8eb7e44c2842db98730717c75cc94c96ab9ae60f079879e756980b4003b38fb449203f"
        "7237cb9f81077b8ac49c75c8115ed408312222eab61e18feca17"
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
        userdevice.start_new_session(
            ephemeral_key=KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
        )
        self.next_step()

        # Test step 4
        cmds_select = userdevice.wait_for_command()
        if cmds_select.ins == INS.SELECT:
            userdevice.handle_select(
                cmds,
            )
        else:
            return  # chekc with the group
        self.next_step()

        # Test step 5
        cmds_auth0 = userdevice.wait_for_command()
        if cmds_auth0.ins == INS.AUTH0:
            userdevice.handle_auth0(
                cmds_auth0,
            )
        else:
            return  # chekc with the group
        self.next_step()

        # Test step 6
        cmds_auth1 = userdevice.wait_for_command()
        if cmds_auth1.ins == INS.AUTH1:
            userdevice.handle_auth1(
                cmds_auth1,
            )
        else:
            return  # chekc with the group
        self.next_step()

        # Test step 7
        cmds_control_flow = userdevice.wait_for_command()
        if cmds_control_flow.ins == INS.CONTROL_FLOW:
            userdevice.handle_control_flow(
                cmds_control_flow,
            )
        else:
            return  # check with the group
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_NFC_STDTXN_30 Cleanup")
