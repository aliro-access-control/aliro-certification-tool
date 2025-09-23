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
    CryptogramNotFound,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors
from binascii import hexlify
import time


class NFC_UD_NEG_AUTH0_DIFFERENT_CRYPTOGRAM_CONSECUTIVE_FAST(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_NEG_AUTH0_DIFFERENT_CRYPTOGRAM_CONSECUTIVE_FAST",
        "version": "0.0.1",
        "title": "NFC_UD_NEG_AUTH0_DIFFERENT_CRYPTOGRAM_CONSECUTIVE_FAST",
        "description": """Verify conformance of User Device UT in AUTH0 command.""",
    }

    reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8"
        "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
        "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
    )
    reader_ePuBK_2 = bytes.fromhex(
        "04f39b4ca9ffdf7b6af338af3c7c7a7973794652a2354"
        "a966b5cc0fef88e9f3a9211930161aab3d9baf77a81898"
        "e768afcce6db853b170489db3c08fd168e159a4"
    )
    reader_ePrivK = bytes.fromhex(
        "3c0f74114cd2a021e8066efbaa31dbb97ef0054272192606fd96633a04f66214"
    )
    reader_ePrivK_2 = bytes.fromhex(
        "e20ca94fba4c29d65d20456029da9ab45921075cdaed72cd5d1dcc5e552023f8"
    )
    transaction_identifier = bytes.fromhex("4165A83667AD0AF5AB115247424822E0")
    transaction_identifier_2 = bytes.fromhex("3d4fa85d4bfcf30b61b804eb9b3ff7cc")

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
            TestStep("Step3: Transaction initiation (fast)"),
            TestStep("Step4: Send/Receive AUTH0 command/response"),
            TestStep("Step5: Send/Receive Select command/response"),
            TestStep("Step6: Send/Receive second AUTH0 command/response"),
        ]

    async def setup(self) -> None:
        logger.info("NFC_UD_NEG_AUTH0_DIFFERENT_CRYPTOGRAM_CONSECUTIVE_FAST setup")
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
            transaction_identifier_list=[
                self.transaction_identifier,
                self.transaction_identifier_2,
            ],
            ephemeral_key_list=[
                KeyPair(self.reader_ePrivK, self.reader_ePuBK),
                KeyPair(self.reader_ePrivK_2, self.reader_ePuBK_2),
            ],
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
        
        # Test Step 3
        try:
            await self.reader.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 4
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.FAST,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except CryptogramNotFound as error:
            logger.info(str(error))
            logger.info("Cryptogram decryption failed as expected, because Expedited Standard phase was not executed.")
            pass
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        first_credential_ephemeral_key = self.reader.session.credential_ephemeral_key.as_bytes()
        first_received_cryptogram = self.reader.session.received_cryptogram
        self.next_step()

        # Wait for 3 seconds
        time.sleep(3)
        
        # Test step 5
        try:
            await self.reader.handle_select(aid=EXPEDITED_PHASE_AID)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 6
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.FAST,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except CryptogramNotFound as error:
            logger.info(str(error))
            logger.info("Second cryptogram decryption failed as expected, because Expedited Standard phase was not executed.")
            pass
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        
        second_credential_ephemeral_key = self.reader.session.credential_ephemeral_key.as_bytes()
        second_received_cryptogram = self.reader.session.received_cryptogram

        logger.info("First cryptogram: {!r}".format(hexlify(first_received_cryptogram)))
        logger.info("First credential ephemeral public key: {!r}".format(hexlify(first_credential_ephemeral_key)))
        logger.info("Second cryptogram: {!r}".format(hexlify(second_received_cryptogram)))
        logger.info("Second credential ephemeral public key: {!r}".format(hexlify(second_credential_ephemeral_key)))
        if second_received_cryptogram == first_received_cryptogram:
            self.mark_step_failure("Received cryptogram same as previous response.")
            return
        if second_credential_ephemeral_key == first_credential_ephemeral_key:
            self.mark_step_failure("Received credential epubk same as previous response.")
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_NEG_AUTH0_DIFFERENT_CRYPTOGRAM_CONSECUTIVE_FAST Cleanup")
        await self.reader.transaction_termination()
