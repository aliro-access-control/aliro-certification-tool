from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
    S2,
    ReaderStatus,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
    InvalidStatusError,
)
from aliro_actuator.access_protocol.reader import Reader, ReaderMode
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from aliro_actuator.trust_framework.errors import InvalidKeyError
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class NFC_UD_NEG_AUTH0_EXTRA_TAG(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_NEG_AUTH0_EXTRA_TAG",
        "version": "0.0.1",
        "title": "NFC_UD_NEG_AUTH0_EXTRA_TAG",
        "description": """Verify conformance of User Device UT in AUTH0 command, invalid reader_ePubK.""",
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
            TestStep("Step3: Set the User Device UT"),
            TestStep("Step4: Send/Receive Select command/response"),
            TestStep("Step5: Send/Receive AUTH0 command/response"),
            TestStep("Step6: Send/Receive AUTH1 command/response"),
            TestStep("Step7: Send/Receive EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("UD_NFC_AUTH0_12 setup")
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
            mode=ReaderMode.READER,
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
        reader_ePuBK = bytes.fromhex(
            "049696afe33de58b7d3253d1cba86d14147c16d455e8"
            "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
            "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
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
        await self.reader.setup_connection()  # up to RATS command/ ATS response
        self.reader.start_new_session()
        self.next_step()

        # Test step 4
        try:
            await self.reader.handle_select(aid=EXPEDITED_PHASE_AID)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5
        try:
            auth0_response = await self.reader.command_auth0(
                transaction=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
                protocol_version=PROTOCOL_VERSION,
                reader_epubk=reader_ePuBK,
                transaction_identifier=self.reader.session.transaction_identifier,
                reader_identifier=self.reader.reader_group_identifier
                + self.reader.reader_group_sub_identifier,
                extra_tlv=bytes.fromhex("010203"),
            )
        except InvalidStatusError as error:
            self.mark_step_failure(str(error))
            return
        except InvalidResponseError as error:
            logger.error("AUTH0 response format invalid")
            self.mark_step_failure(str(error))
            return

        logger.info("Handling AUTH0 response")
        logger.info("Checking access credential ephemeral public key")
        try:
            credential_ephemeral_public_key = PublicKey(auth0_response.credential_epubk)
        except InvalidKeyError as error:
            self.mark_step_failure(str(error))
            return
        logger.info("Access credential ephemeral public key is a valid key")

        logger.info("Saving Auth0 response data to session")
        self.reader.session.set_flag(Transaction.STANDARD, AuthenticationPolicy.USER_DEVICE)
        self.reader.session.set_credential_ephemeral_key(credential_ephemeral_public_key)
        self.reader.session.set_response_vendor_extension(
            auth0_response.vendor_specific_extensions
        )

        # Test step 6
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test step 7
        try:
            await self.reader.handle_exchange(
                False, reader_status=ReaderStatus.READER_STATE_UNSECURED
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
    async def cleanup(self) -> None:
        logger.info("NFC_UD_NEG_AUTH0_EXTRA_TAG Cleanup")
        await self.reader.transaction_termination()
