from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
    ReaderStatus,
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

import random

class NFC_UD_NEG_AUTH0_UNKNOWN_READER_ID(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_NEG_AUTH0_UNKNOWN_READER_ID",
        "version": "0.0.1",
        "title": "NFC_UD_NEG_AUTH0_UNKNOWN_READER_ID",
        "description": """Expedited Standard Phase With Unknown Reader Group Identifier.""",
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
    #unknown_reader_identifier = bytes.fromhex("00113344667799AA00113344667799AA113344667799AA00113344667799AA44")
    unknown_reader_identifier = bytes.fromhex("AA113344667799AA00113344667799AA44F758971AA4213544F758971AA42135")
    
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
            TestStep("Step3: Transaction initiation"), #include select command and response
            TestStep("Step4: Send/Receive AUTH0 command (with unknown reader_identifier)/response"),
            TestStep("Step5: Send/Receive AUTH1 command/response"),
            TestStep("Step6: Send/Receive EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
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
        self.reader.reader_identifier = self.unknown_reader_identifier #overriding the known reader_identifier with unknown_reader_identifier

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
        authentication_policy = random.randint(
            AuthenticationPolicy.USER_DEVICE, 
            AuthenticationPolicy.FORCE_USER_AUTHENTICATION
        )
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy(authentication_policy),
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
        self.next_step()
        
        # Test step 6
        try:
            await self.reader.handle_exchange(
                False, reader_status=ReaderStatus.READER_STATE_UNSECURED
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_NEG_AUTH0_UNKNOWN_READER_ID Cleanup")
        await self.reader.transaction_termination()
