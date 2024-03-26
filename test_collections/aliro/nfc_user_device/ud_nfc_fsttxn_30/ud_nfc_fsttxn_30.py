from aliro_actuator.access_protocol import TransportProtocol
from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    Transaction,
    TransactionCode,
)
from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
    CryptogramNotFound
)

from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase

class UD_NFC_FSTTXN_30(AliroUserDeviceTestCase, UserPromptSupport):
        metadata = {
            "public_id": "UD-NFC-FSTTXN-3.0",
            "version": "0.0.1",
            "title": "UD-NFC-FSTTXN-3.0",
            "description": """Verify conformance of User Device UT in CONTROL_FLOW command.""",
        }

        reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8"
        "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
        "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
        )
        
        reader_ePrivK = bytes.fromhex(
        "3c0f74114cd2a021e8066efbaa31dbb97ef0054272192606fd96633a04f66214"
        )
        
        transaction_identifier = bytes.fromhex("4165A83667AD0AF5AB115247424822E0")

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
                TestStep("Step2: Set to Polling mode"),
                TestStep("Step3: Set the User Device UT"),
                TestStep("Step4: Send/Receive Select command/response"),
                TestStep("Step5: Send/Receive AUTH0 command/response"),
                TestStep("Step6: Send/Receive CONTROL_FLOW command/response"),
            ]

        async def setup(self) -> None:
            logger.info("This is a test case setup")


        async def execute(self) -> None:
            #Test Step 1
            #load parameters from project config
            group_id = self.th_group_identifier()
            sub_group_id = self.th_sub_group_identifier()
            key = self.th_reader_keypair()

            #Initialize Aliro NFC Reader
            reader = Reader(
                        transport_protocol=TransportProtocol.NFC,
                        reader_group_identifier=group_id,
                        reader_group_sub_identifier=sub_group_id,
                        reader_key=key,
                    )
            self.next_step()


            #Test Step 2
            #Display pop-up to the put the User Device UT on the TH
            await self.send_prompt_request(
                    OptionsSelectPromptRequest(
                        prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
                    )
                )
            self.next_step()

            #Test Step 3
            reader.transaction_initiation()
            reader.start_new_session(
                    transaction_identifier=self.transaction_identifier,
                    ephemeral_key=KeyPair(self.reader_ePrivK, self.reader_ePuBK),
                )
            self.next_step()

            # Test step 4
            # Select response is expected
            try:
                reader.handle_select(aid=EXPEDITED_PHASE_AID)
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(error)
                return
            self.next_step()

            # Test Step 5
            # Handles AUTH0 response and transaction type is fast.
            # Also initializes reader storage and handles cryptogram checking
            try:
                reader.handle_auth0(
                    transaction_type=Transaction.FAST,
                    transaction_code=TransactionCode.USER_DEVICE,
                )
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(error)
                return
            except CryptogramNotFound as error:
                # Handler Cryptogram not Found error
                self.mark_step_failure(error)
                return
            self.next_step()

            #Test Step 6
            try:
                reader.handle_control_flow(
                    success=True,
                )
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(error)
                return
            self.next_step()

        async def cleanup(self) -> None:
            logger.info("UD_NFC_FSTTXN_30 Cleanup")
