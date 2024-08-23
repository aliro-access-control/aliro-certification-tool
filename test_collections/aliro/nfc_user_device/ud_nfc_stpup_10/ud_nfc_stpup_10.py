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
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.response import DeviceResponse
from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class UD_NFC_STPUP_10(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-NFC-STPUP-1.0",
        "version": "0.0.1",
        "title": "UD-NFC-STPUP-1.0",
        "description": """Verify conformance of User Device UT in GET RESPONSE command.""",
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

    request = bytes.fromhex(
        "A2613163312E30613282A16131D818581FA2613567616C69726F2D616131A"
        "167616C69726F2D61A166666C6F6F7231F4A16131D818581FA2613567616C"
        "69726F2D726131A167616C69726F2D72A166666C6F6F7232F5"
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
            TestStep("Step1: Prerequisites"),
            TestStep("Step2: Receive Envelope"),
            TestStep("Step3: Send Get Response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        cert = self.th_reader_certificate()

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            reader_cert=cert,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
        )


    @log_errors
    async def execute(self) -> None:
        # Prerequisites
        # Display pop-up to put the User Device UT on the TH
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
            )
        )

        try:
            await self.reader.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        try:
            await self.reader.expedited_transaction_standard(
                AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 2 and 3
        try:
            response = await self.reader.handle_envelope(self.request)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        # Parse response
        device_response = DeviceResponse()
        if device_response.from_cbor(response):
            logger.info("Successfully parsed the CBOR to populate a Device Response.")
        else:
            self.mark_step_failure("Failed to parse the CBOR.")
            return

        # Validate response
        if not device_response.is_valid():
            self.mark_step_failure("Failed to validate device response.")
            return

        self.next_step()
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_NFC_STPUP_10 Cleanup")
        await self.reader.transaction_termination()
