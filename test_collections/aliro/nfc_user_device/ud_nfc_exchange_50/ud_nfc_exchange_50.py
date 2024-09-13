from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class UD_NFC_EXCHANGE_50(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-NFC-EXCHANGE-5.0",
        "version": "0.0.1",
        "title": "UD-NFC-EXCHANGE-5.0",
        "description": """Verify conformance of User Device UT in EXCHANGE command.""",
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
            TestStep("Step2: Set to polling mode"),
            TestStep("Step3: Transaction initiation"),
            TestStep("Step4: Send/Receive AUTH0 command/response"),
            TestStep("Step5: Send/Receive AUTH1 command/response"),
            TestStep("Step6: Send/Receive EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("UD_NFC_EXCHANGE_50 setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
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
        try:
            await self.reader.transaction_initiation()  # including SELECT command
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 4
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        bitmap_1 = self.reader.session.signaling_bitmap[1]
        if not (bitmap_1 & (1 << 4) == (1 << 4)):
            self.mark_step_failure("Auth1 response indicates mailbox cannot be read")
            return
        self.next_step()

        # Test step 6
        try:
            result = await self.reader.handle_exchange(
                False, read_requests=[(0x00, 0x08)]
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        if len(result) == 0:
            self.mark_step_failure("Exchange response did not return a read result")
            return
        if len(result) > 1:
            self.mark_step_failure(
                "Exchange response returned more than 1 read result, "
                "while only one was requested"
            )
            return
        if len(result[0]) != 0x08:
            self.mark_step_failure(
                "Exchange response read result has invalid length, "
                "requested: 0x08, got 0x{:04x}".format(len(result[0]))
            )
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_NFC_EXCHANGE_50 Cleanup")
        await self.reader.transaction_termination()
