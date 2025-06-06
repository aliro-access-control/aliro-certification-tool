from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    STEPUP_PHASE_AID,
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

from test_collections.aliro.support.access_doc.mdl.common import DocTypes
from test_collections.aliro.support.access_doc.mdl.response import DeviceResponse
from test_collections.aliro.support.access_doc.mdl.request.device_request_builder import DeviceRequestBuilder, RequestElement
from test_collections.aliro.support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class NFC_UD_STEPUP_AD(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_STEPUP_AD",
        "version": "0.0.1",
        "title": "NFC_UD_STEPUP_AD",
        "description": """Verify conformance of User Device UT in ENVELOPE and GET RESPONSE command.""",
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
            TestStep("Step1: Select Routine"),
            TestStep("Step2: Auth0 Routine"),
            TestStep("Step3: Auth1 Routine"),
            TestStep("Step4: Select Routine for STEPUP AID (optional)"),
            TestStep("Step5: Request Access Document"),
            TestStep("Step6: Exchange Routine")
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

        # Build the Device Request.
        self.issuer_public_key, self.element_id = self.th_access_document_data()
        self.request = DeviceRequestBuilder.build(
            [RequestElement(self.element_id, False)], []
        ).to_cbor()
        logger.info(f"Generated Device Request: {self.request.hex()}")


    @log_errors
    async def execute(self) -> None:
        # Test step 1
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
        self.next_step()

        # Test step 2 & 3
        try:
            await self.reader.expedited_transaction_standard(
                AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        self.next_step()

        # Test step 4
        try:
            if self.reader.session.step_up_aid_select_required():
                logger.info("Step-up AID SELECT command required")
                await self.reader.handle_select(STEPUP_PHASE_AID)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5
        try:
            response = await self.reader.handle_envelope(self.request)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        # Parse response
        logger.info(f"Cbor = {response.hex()}")
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

        # Validate hash and signature
        for document in device_response.documents:
            if document.doc_type != DocTypes.ALIRO_ACCESS:
                self.mark_step_failure("Document DocType is invalid.")
                return

            if not document.check_signature(
                    self.issuer_public_key.as_bytes(),
                    self.reader.session.credential_pubk.as_bytes()
            ):
                self.mark_step_failure("Document signature is invalid.")
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
        logger.info("NFC_UD_STEPUP_AD Cleanup")
        await self.reader.transaction_termination()
